//! 符号化 + 回溯（§4.2 / §13.1）。

use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use thiserror::Error;

#[cfg(test)]
use introspect_schema::SymbolConfidence;
use introspect_schema::Symbolized;

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymbolizeError {
    #[error("地址 {addr} 超出已知符号范围")]
    NotFound { addr: String },
    #[error("符号文件不可获得")]
    NoSymbolFile,
    #[error("blazesym 后端调用失败：{reason}")]
    Backend { reason: String },
    #[error("符号化请求队列已满")]
    QueueFull,
    #[error("符号化请求超时")]
    Timeout,
    #[error("符号化 worker 已停止")]
    WorkerStopped,
    #[error("符号化 worker panic")]
    WorkerPanic,
    #[error("符号化 worker 关闭超时")]
    ShutdownTimeout,
}

impl SymbolizeError {
    pub const fn kind(&self) -> &'static str {
        match self {
            SymbolizeError::NotFound { .. } => "not_found",
            SymbolizeError::NoSymbolFile => "no_symbol_file",
            SymbolizeError::Backend { .. } => "backend",
            SymbolizeError::QueueFull => "queue_full",
            SymbolizeError::Timeout => "timeout",
            SymbolizeError::WorkerStopped => "worker_stopped",
            SymbolizeError::WorkerPanic => "worker_panic",
            SymbolizeError::ShutdownTimeout => "shutdown_timeout",
        }
    }
}

pub trait Symbolizer: Send + Sync {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError>;

    fn cross_check(&self, _addr: u64, _expected_top_frame: &str) -> Option<String> {
        None
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FallbackSymbolizer;

impl Symbolizer for FallbackSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        Err(SymbolizeError::NotFound {
            addr: format!("{addr:#x}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolizerWorkerConfig {
    pub queue_capacity: usize,
    pub request_timeout: Duration,
}

impl Default for SymbolizerWorkerConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 64,
            request_timeout: Duration::from_millis(250),
        }
    }
}

struct SymbolizeRequest {
    addr: u64,
    reply: SyncSender<Result<Symbolized, SymbolizeError>>,
}

trait WorkerBackend {
    fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    Running,
    Executing,
    ShutdownRequested,
    Stopped,
    Panicked,
}

struct WorkerLifecycle {
    state: Mutex<WorkerState>,
    changed: Condvar,
}

impl WorkerLifecycle {
    fn new() -> Self {
        Self {
            state: Mutex::new(WorkerState::Running),
            changed: Condvar::new(),
        }
    }

    fn terminal_error(&self) -> Option<SymbolizeError> {
        match *self.state.lock().unwrap() {
            WorkerState::Running | WorkerState::Executing => None,
            WorkerState::ShutdownRequested | WorkerState::Stopped => {
                Some(SymbolizeError::WorkerStopped)
            }
            WorkerState::Panicked => Some(SymbolizeError::WorkerPanic),
        }
    }

    fn begin_request(&self) -> Result<(), SymbolizeError> {
        let mut state = self.state.lock().unwrap();
        match *state {
            WorkerState::Running => {
                *state = WorkerState::Executing;
                self.changed.notify_all();
                Ok(())
            }
            WorkerState::ShutdownRequested | WorkerState::Stopped => {
                Err(SymbolizeError::WorkerStopped)
            }
            WorkerState::Panicked => Err(SymbolizeError::WorkerPanic),
            WorkerState::Executing => unreachable!("worker executes one request at a time"),
        }
    }

    fn finish_request(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        match *state {
            WorkerState::Executing => {
                *state = WorkerState::Running;
                self.changed.notify_all();
                false
            }
            WorkerState::ShutdownRequested | WorkerState::Stopped | WorkerState::Panicked => true,
            WorkerState::Running => unreachable!("request was not marked executing"),
        }
    }

    fn request_shutdown(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, WorkerState::Running | WorkerState::Executing) {
            *state = WorkerState::ShutdownRequested;
            self.changed.notify_all();
            true
        } else {
            false
        }
    }

    fn is_shutdown_requested(&self) -> bool {
        matches!(
            *self.state.lock().unwrap(),
            WorkerState::ShutdownRequested | WorkerState::Stopped
        )
    }

    fn mark_stopped(&self) {
        let mut state = self.state.lock().unwrap();
        if *state != WorkerState::Panicked {
            *state = WorkerState::Stopped;
            self.changed.notify_all();
        }
    }

    fn mark_panicked(&self) {
        let mut state = self.state.lock().unwrap();
        *state = WorkerState::Panicked;
        self.changed.notify_all();
    }

    #[cfg(test)]
    fn wait_for_state(&self, expected: WorkerState, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, wait) = self
            .changed
            .wait_timeout_while(state, timeout, |state| *state != expected)
            .unwrap();
        !wait.timed_out() && *state == expected
    }
}

#[derive(Clone)]
pub struct SymbolizerWorkerClient {
    requests: SyncSender<SymbolizeRequest>,
    request_timeout: Duration,
    lifecycle: Arc<WorkerLifecycle>,
}

impl SymbolizerWorkerClient {
    fn symbolize_inner<BeforeSend, AfterSend>(
        &self,
        addr: u64,
        before_send: BeforeSend,
        after_send: AfterSend,
    ) -> Result<Symbolized, SymbolizeError>
    where
        BeforeSend: FnOnce(),
        AfterSend: FnOnce(),
    {
        if let Some(error) = self.lifecycle.terminal_error() {
            return Err(error);
        }

        let (reply, response) = mpsc::sync_channel(1);
        before_send();
        match self.requests.try_send(SymbolizeRequest { addr, reply }) {
            Ok(()) => after_send(),
            Err(TrySendError::Full(_)) => return Err(SymbolizeError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                return Err(self
                    .lifecycle
                    .terminal_error()
                    .unwrap_or(SymbolizeError::WorkerStopped))
            }
        }

        match response.recv_timeout(self.request_timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(SymbolizeError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(self
                .lifecycle
                .terminal_error()
                .unwrap_or(SymbolizeError::WorkerStopped)),
        }
    }
}

impl Symbolizer for SymbolizerWorkerClient {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        self.symbolize_inner(addr, || {}, || {})
    }

    fn cross_check(&self, addr: u64, expected_top_frame: &str) -> Option<String> {
        let symbol = match self.symbolize(addr) {
            Ok(symbol) => symbol.name,
            Err(error) => return Some(format!("符号化失败：{error}")),
        };
        let actual = symbol.split('+').next().unwrap_or(&symbol);
        let expected = expected_top_frame
            .split('+')
            .next()
            .unwrap_or(expected_top_frame);
        if actual == expected {
            None
        } else {
            Some(format!(
                "wchan/symbol={actual} 与 stack顶帧={expected} 不自洽"
            ))
        }
    }
}

pub struct SymbolizerWorkerHandle {
    shutdown: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
    lifecycle: Arc<WorkerLifecycle>,
    shutdown_timeout: Duration,
}

impl SymbolizerWorkerHandle {
    pub fn shutdown(mut self) -> Result<(), SymbolizeError> {
        let shutdown_requested = self.lifecycle.request_shutdown();
        let _ = self.shutdown.send(());
        let join = self.join.take().ok_or(SymbolizeError::WorkerStopped)?;
        let started = Instant::now();
        while !join.is_finished() {
            let elapsed = started.elapsed();
            if elapsed >= self.shutdown_timeout {
                return Err(SymbolizeError::ShutdownTimeout);
            }
            thread::sleep(WORKER_POLL_INTERVAL.min(self.shutdown_timeout - elapsed));
        }
        match join.join() {
            Ok(()) if shutdown_requested => Ok(()),
            Ok(()) => Err(SymbolizeError::WorkerStopped),
            Err(_) => Err(SymbolizeError::WorkerPanic),
        }
    }
}

impl Drop for SymbolizerWorkerHandle {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.lifecycle.request_shutdown();
            let _ = self.shutdown.send(());
        }
    }
}

pub fn spawn_kernel_symbolizer(
    config: SymbolizerWorkerConfig,
) -> Result<(SymbolizerWorkerClient, SymbolizerWorkerHandle), SymbolizeError> {
    #[cfg(target_os = "linux")]
    {
        spawn_worker(config, KernelBlazeBackend::new)
    }
    #[cfg(not(target_os = "linux"))]
    {
        spawn_worker::<UnavailableKernelBackend, _>(config, || Err(SymbolizeError::NoSymbolFile))
    }
}

struct InjectedSymbolizerBackend {
    symbolizer: Arc<dyn Symbolizer>,
}

impl WorkerBackend for InjectedSymbolizerBackend {
    fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        self.symbolizer.symbolize(addr)
    }
}

#[doc(hidden)]
pub fn spawn_injected_symbolizer_worker(
    config: SymbolizerWorkerConfig,
    symbolizer: Arc<dyn Symbolizer>,
) -> Result<(SymbolizerWorkerClient, SymbolizerWorkerHandle), SymbolizeError> {
    spawn_worker(config, move || Ok(InjectedSymbolizerBackend { symbolizer }))
}

fn spawn_worker<B, F>(
    config: SymbolizerWorkerConfig,
    factory: F,
) -> Result<(SymbolizerWorkerClient, SymbolizerWorkerHandle), SymbolizeError>
where
    B: WorkerBackend + 'static,
    F: FnOnce() -> Result<B, SymbolizeError> + Send + 'static,
{
    let (requests, request_rx) = mpsc::sync_channel(config.queue_capacity);
    let (shutdown, shutdown_rx) = mpsc::channel();
    let (initialized, initialized_rx) = mpsc::sync_channel(1);
    let lifecycle = Arc::new(WorkerLifecycle::new());
    let worker_lifecycle = Arc::clone(&lifecycle);

    let join = thread::Builder::new()
        .name("fovea-symbolizer".into())
        .spawn(move || {
            let mut backend = match catch_unwind(AssertUnwindSafe(factory)) {
                Ok(Ok(backend)) => backend,
                Ok(Err(error)) => {
                    worker_lifecycle.mark_stopped();
                    let _ = initialized.send(Err(error));
                    return;
                }
                Err(payload) => {
                    worker_lifecycle.mark_panicked();
                    drop(initialized);
                    std::panic::resume_unwind(payload);
                }
            };
            if initialized.send(Ok(())).is_err() {
                worker_lifecycle.mark_stopped();
                return;
            }
            worker_loop(&mut backend, request_rx, shutdown_rx, worker_lifecycle);
        })
        .map_err(|error| SymbolizeError::Backend {
            reason: error.to_string(),
        })?;

    match initialized_rx.recv() {
        Ok(Ok(())) => Ok((
            SymbolizerWorkerClient {
                requests,
                request_timeout: config.request_timeout,
                lifecycle: Arc::clone(&lifecycle),
            },
            SymbolizerWorkerHandle {
                shutdown,
                join: Some(join),
                lifecycle,
                shutdown_timeout: config.request_timeout,
            },
        )),
        Ok(Err(error)) => {
            let _ = join.join();
            Err(error)
        }
        Err(_) => {
            let _ = join.join();
            Err(SymbolizeError::WorkerPanic)
        }
    }
}

fn worker_loop<B: WorkerBackend>(
    backend: &mut B,
    requests: Receiver<SymbolizeRequest>,
    shutdown: Receiver<()>,
    lifecycle: Arc<WorkerLifecycle>,
) {
    loop {
        match shutdown.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                let _ = lifecycle.request_shutdown();
            }
            Err(TryRecvError::Empty) => {}
        }
        if lifecycle.is_shutdown_requested() {
            reject_pending_requests(&requests, SymbolizeError::WorkerStopped);
            lifecycle.mark_stopped();
            return;
        }

        match requests.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(request) => {
                if let Err(error) = lifecycle.begin_request() {
                    let _ = request.reply.send(Err(error.clone()));
                    reject_pending_requests(&requests, error);
                    lifecycle.mark_stopped();
                    return;
                }
                let result = catch_unwind(AssertUnwindSafe(|| backend.symbolize(request.addr)));
                match result {
                    Ok(result) => {
                        let _ = request.reply.send(result);
                        if lifecycle.finish_request() {
                            reject_pending_requests(&requests, SymbolizeError::WorkerStopped);
                            lifecycle.mark_stopped();
                            return;
                        }
                    }
                    Err(payload) => {
                        lifecycle.mark_panicked();
                        let _ = request.reply.send(Err(SymbolizeError::WorkerPanic));
                        reject_pending_requests(&requests, SymbolizeError::WorkerPanic);
                        std::panic::resume_unwind(payload);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                lifecycle.mark_stopped();
                return;
            }
        }
    }
}

fn reject_pending_requests(requests: &Receiver<SymbolizeRequest>, error: SymbolizeError) {
    while let Ok(request) = requests.try_recv() {
        let _ = request.reply.send(Err(error.clone()));
    }
}

#[cfg(target_os = "linux")]
struct KernelBlazeBackend {
    inner: blazesym::symbolize::Symbolizer,
    source: blazesym::symbolize::source::Source<'static>,
}

#[cfg(target_os = "linux")]
impl KernelBlazeBackend {
    fn new() -> Result<Self, SymbolizeError> {
        Ok(Self {
            inner: blazesym::symbolize::Symbolizer::new(),
            source: blazesym::symbolize::source::Source::Kernel(
                blazesym::symbolize::source::Kernel::default(),
            ),
        })
    }
}

#[cfg(target_os = "linux")]
impl WorkerBackend for KernelBlazeBackend {
    fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        let symbolized = self
            .inner
            .symbolize_single(&self.source, blazesym::symbolize::Input::AbsAddr(addr))
            .map_err(map_blaze_error)?;
        blaze_to_symbolized(symbolized, addr)
    }
}

#[cfg(target_os = "linux")]
fn map_blaze_error(error: blazesym::Error) -> SymbolizeError {
    match error.kind() {
        blazesym::ErrorKind::NotFound => SymbolizeError::NoSymbolFile,
        _ => SymbolizeError::Backend {
            reason: format!("{error:#}"),
        },
    }
}

#[cfg(any(target_os = "linux", test))]
fn blaze_to_symbolized(
    symbolized: blazesym::symbolize::Symbolized<'_>,
    addr: u64,
) -> Result<Symbolized, SymbolizeError> {
    match symbolized {
        blazesym::symbolize::Symbolized::Sym(symbol) => Ok(Symbolized {
            name: format!("{}+0x{:x}", symbol.name, symbol.offset),
            source: kernel_blaze_confidence(&symbol),
        }),
        blazesym::symbolize::Symbolized::Unknown(blazesym::symbolize::Reason::MissingSyms) => {
            Err(SymbolizeError::NoSymbolFile)
        }
        blazesym::symbolize::Symbolized::Unknown(_) => Err(SymbolizeError::NotFound {
            addr: format!("{addr:#x}"),
        }),
    }
}

#[cfg(any(target_os = "linux", test))]
fn kernel_blaze_confidence(
    symbol: &blazesym::symbolize::Sym<'_>,
) -> introspect_schema::SymbolConfidence {
    use introspect_schema::SymbolConfidence;

    if symbol.code_info.is_some() {
        SymbolConfidence::Dwarf
    } else if !symbol.name.is_empty() {
        SymbolConfidence::Kallsyms
    } else {
        SymbolConfidence::None
    }
}

#[cfg(not(target_os = "linux"))]
struct UnavailableKernelBackend;

#[cfg(not(target_os = "linux"))]
impl WorkerBackend for UnavailableKernelBackend {
    fn symbolize(&mut self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
        Err(SymbolizeError::NoSymbolFile)
    }
}

#[cfg(test)]
pub fn make_symbolized(name: impl Into<String>, confidence: SymbolConfidence) -> Symbolized {
    Symbolized {
        name: name.into(),
        source: confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    fn config(queue_capacity: usize, request_timeout: Duration) -> SymbolizerWorkerConfig {
        SymbolizerWorkerConfig {
            queue_capacity,
            request_timeout,
        }
    }

    #[test]
    fn fallback_symbolizer_returns_not_found() {
        let s = FallbackSymbolizer;
        let r = s.symbolize(0xffffffff81a2b3c4);
        match r {
            Err(SymbolizeError::NotFound { addr }) => {
                assert!(addr.contains("0x"), "addr 形态要含 0x 前缀: {addr}");
            }
            other => panic!("FallbackSymbolizer 必须 Err NotFound; 实际 {other:?}"),
        }
    }

    #[test]
    fn fallback_cross_check_is_silent_none() {
        let s = FallbackSymbolizer;
        assert!(s.cross_check(0xdeadbeef, "anything").is_none());
    }

    #[test]
    fn blazesym_025_conversion_uses_offset_and_reason_paths() {
        let symbolizer = blazesym::symbolize::Symbolizer::new();
        let source: blazesym::symbolize::source::Source<'static> =
            blazesym::symbolize::source::Source::Kernel(
                blazesym::symbolize::source::Kernel::default(),
            );
        let _symbolize_single =
            || symbolizer.symbolize_single(&source, blazesym::symbolize::Input::AbsAddr(0_u64));

        let symbol = blazesym::symbolize::Sym {
            name: Cow::Borrowed("schedule"),
            module: None,
            addr: 0x1000,
            offset: 0x20,
            size: None,
            code_info: None,
            inlined: Box::new([]),
            _non_exhaustive: (),
        };
        let converted =
            blaze_to_symbolized(blazesym::symbolize::Symbolized::Sym(symbol), 0x1020).unwrap();
        assert_eq!(converted.name, "schedule+0x20");
        assert_eq!(converted.source, SymbolConfidence::Kallsyms);

        let error = blaze_to_symbolized(
            blazesym::symbolize::Symbolized::Unknown(blazesym::symbolize::Reason::MissingSyms),
            0x1020,
        )
        .unwrap_err();
        assert_eq!(error, SymbolizeError::NoSymbolFile);
        let error = blaze_to_symbolized(
            blazesym::symbolize::Symbolized::Unknown(blazesym::symbolize::Reason::UnknownAddr),
            0x1020,
        )
        .unwrap_err();
        assert_eq!(
            error,
            SymbolizeError::NotFound {
                addr: "0x1020".into()
            }
        );
    }

    struct EchoBackend {
        _thread_owned: Rc<()>,
    }

    impl WorkerBackend for EchoBackend {
        fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            Ok(make_symbolized(
                format!("frame_{addr}+0x0"),
                SymbolConfidence::Kallsyms,
            ))
        }
    }

    #[test]
    fn worker_success_with_thread_owned_non_send_backend() {
        let caller_thread = thread::current().id();
        let (factory_thread, factory_thread_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(config(4, Duration::from_secs(1)), move || {
            let current = thread::current();
            factory_thread
                .send((current.id(), current.name().map(str::to_owned)))
                .unwrap();
            Ok(EchoBackend {
                _thread_owned: Rc::new(()),
            })
        })
        .unwrap();

        let (backend_thread, backend_thread_name) = factory_thread_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_ne!(backend_thread, caller_thread);
        assert_eq!(backend_thread_name.as_deref(), Some("fovea-symbolizer"));
        let symbol = client.symbolize(7).unwrap();
        assert_eq!(symbol.name, "frame_7+0x0");
        assert!(client.cross_check(7, "frame_7+0x44").is_none());
        assert!(client.cross_check(7, "schedule+0x10").is_some());
        handle.shutdown().unwrap();
    }

    struct ErrorBackend;

    impl WorkerBackend for ErrorBackend {
        fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            match addr {
                1 => Err(SymbolizeError::NotFound { addr: "0x1".into() }),
                2 => Err(SymbolizeError::Backend {
                    reason: "fixture backend".into(),
                }),
                _ => Err(SymbolizeError::NoSymbolFile),
            }
        }
    }

    #[test]
    fn worker_preserves_not_found_backend_and_no_symbol_errors() {
        let (client, handle) =
            spawn_worker(config(4, Duration::from_secs(1)), || Ok(ErrorBackend)).unwrap();

        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::NotFound { addr: "0x1".into() }
        );
        assert_eq!(
            client.symbolize(2).unwrap_err(),
            SymbolizeError::Backend {
                reason: "fixture backend".into()
            }
        );
        assert_eq!(
            client.symbolize(3).unwrap_err(),
            SymbolizeError::NoSymbolFile
        );
        handle.shutdown().unwrap();
    }

    struct BlockingBackend {
        entered: mpsc::Sender<()>,
        release: Receiver<()>,
    }

    impl WorkerBackend for BlockingBackend {
        fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            if addr == 1 {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            Ok(make_symbolized(
                format!("frame_{addr}"),
                SymbolConfidence::Kallsyms,
            ))
        }
    }

    #[test]
    fn request_queue_has_exact_capacity_and_reports_saturation() {
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(config(2, Duration::from_secs(1)), move || {
            Ok(BlockingBackend {
                entered,
                release: release_rx,
            })
        })
        .unwrap();

        let active_client = client.clone();
        let active = thread::spawn(move || active_client.symbolize(1));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (reply_2, response_2) = mpsc::sync_channel(1);
        let (reply_3, response_3) = mpsc::sync_channel(1);
        client
            .requests
            .try_send(SymbolizeRequest {
                addr: 2,
                reply: reply_2,
            })
            .unwrap();
        client
            .requests
            .try_send(SymbolizeRequest {
                addr: 3,
                reply: reply_3,
            })
            .unwrap();
        assert_eq!(client.symbolize(4).unwrap_err(), SymbolizeError::QueueFull);

        release.send(()).unwrap();
        assert_eq!(active.join().unwrap().unwrap().name, "frame_1");
        assert_eq!(
            response_2
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .name,
            "frame_2"
        );
        assert_eq!(
            response_3
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .name,
            "frame_3"
        );
        handle.shutdown().unwrap();
    }

    #[test]
    fn zero_capacity_is_supported_as_a_rendezvous_queue() {
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(config(0, Duration::from_secs(1)), move || {
            Ok(BlockingBackend {
                entered,
                release: release_rx,
            })
        })
        .unwrap();

        let active_client = client.clone();
        let active = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                match active_client.symbolize(1) {
                    Err(SymbolizeError::QueueFull) if std::time::Instant::now() < deadline => {
                        thread::yield_now();
                    }
                    result => break result,
                }
            }
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert_eq!(client.symbolize(2).unwrap_err(), SymbolizeError::QueueFull);

        release.send(()).unwrap();
        assert_eq!(active.join().unwrap().unwrap().name, "frame_1");
        handle.shutdown().unwrap();
    }

    #[test]
    fn request_timeout_is_distinct() {
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(config(1, Duration::from_millis(20)), move || {
            Ok(BlockingBackend {
                entered,
                release: release_rx,
            })
        })
        .unwrap();

        let caller = thread::spawn(move || client.symbolize(1));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(caller.join().unwrap().unwrap_err(), SymbolizeError::Timeout);
        release.send(()).unwrap();
        handle.shutdown().unwrap();
    }

    #[test]
    fn clean_shutdown_stops_future_requests() {
        let (client, handle) = spawn_worker(config(2, Duration::from_secs(1)), || {
            Ok(EchoBackend {
                _thread_owned: Rc::new(()),
            })
        })
        .unwrap();

        handle.shutdown().unwrap();
        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::WorkerStopped
        );
    }

    struct ShutdownRaceBackend {
        entered: mpsc::Sender<()>,
        release: Receiver<()>,
        calls: Arc<AtomicUsize>,
    }

    impl WorkerBackend for ShutdownRaceBackend {
        fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if addr == 1 {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            Ok(make_symbolized(
                format!("frame_{addr}"),
                SymbolConfidence::Kallsyms,
            ))
        }
    }

    #[test]
    fn shutdown_wins_before_racing_request_execution() {
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let backend_calls = Arc::clone(&calls);
        let (client, handle) = spawn_worker(config(2, Duration::from_secs(2)), move || {
            Ok(ShutdownRaceBackend {
                entered,
                release: release_rx,
                calls: backend_calls,
            })
        })
        .unwrap();

        let active_client = client.clone();
        let active = thread::spawn(move || active_client.symbolize(1));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (before_send, before_send_rx) = mpsc::channel();
        let (continue_send, continue_send_rx) = mpsc::channel();
        let (accepted, accepted_rx) = mpsc::channel();
        let racing_client = client.clone();
        let racing = thread::spawn(move || {
            racing_client.symbolize_inner(
                2,
                move || {
                    before_send.send(()).unwrap();
                    continue_send_rx.recv().unwrap();
                },
                move || accepted.send(()).unwrap(),
            )
        });
        before_send_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let lifecycle = Arc::clone(&client.lifecycle);
        let shutdown = thread::spawn(move || handle.shutdown());
        assert!(lifecycle.wait_for_state(WorkerState::ShutdownRequested, Duration::from_secs(1)));

        continue_send.send(()).unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        release.send(()).unwrap();

        assert_eq!(active.join().unwrap().unwrap().name, "frame_1");
        assert_eq!(
            racing.join().unwrap().unwrap_err(),
            SymbolizeError::WorkerStopped
        );
        assert_eq!(shutdown.join().unwrap(), Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    struct PanicBackend;

    impl WorkerBackend for PanicBackend {
        fn symbolize(&mut self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
            panic!("fixture panic");
        }
    }

    #[test]
    fn worker_panic_reaches_request_and_shutdown() {
        let (client, handle) =
            spawn_worker(config(1, Duration::from_secs(1)), || Ok(PanicBackend)).unwrap();

        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::WorkerPanic
        );
        assert_eq!(handle.shutdown(), Err(SymbolizeError::WorkerPanic));
    }

    struct ControlledPanicBackend {
        entered: mpsc::Sender<()>,
        panic_now: Receiver<()>,
    }

    impl WorkerBackend for ControlledPanicBackend {
        fn symbolize(&mut self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            if addr == 1 {
                self.entered.send(()).unwrap();
                self.panic_now.recv().unwrap();
                panic!("controlled fixture panic");
            }
            Ok(make_symbolized(
                format!("frame_{addr}"),
                SymbolConfidence::Kallsyms,
            ))
        }
    }

    #[test]
    fn active_backend_panic_reaches_already_queued_caller() {
        let (entered, entered_rx) = mpsc::channel();
        let (panic_now, panic_now_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(config(2, Duration::from_secs(2)), move || {
            Ok(ControlledPanicBackend {
                entered,
                panic_now: panic_now_rx,
            })
        })
        .unwrap();

        let active_client = client.clone();
        let active = thread::spawn(move || active_client.symbolize(1));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (accepted, accepted_rx) = mpsc::channel();
        let queued_client = client.clone();
        let queued = thread::spawn(move || {
            queued_client.symbolize_inner(2, || {}, move || accepted.send(()).unwrap())
        });
        accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        panic_now.send(()).unwrap();
        assert_eq!(
            active.join().unwrap().unwrap_err(),
            SymbolizeError::WorkerPanic
        );
        assert_eq!(
            queued.join().unwrap().unwrap_err(),
            SymbolizeError::WorkerPanic
        );
        assert_eq!(handle.shutdown(), Err(SymbolizeError::WorkerPanic));
    }

    #[test]
    fn initialization_failure_is_returned() {
        match spawn_worker::<ErrorBackend, _>(config(1, Duration::from_secs(1)), || {
            Err(SymbolizeError::NoSymbolFile)
        }) {
            Err(error) => assert_eq!(error, SymbolizeError::NoSymbolFile),
            Ok(_) => panic!("backend initialization failure must abort spawn"),
        }
    }

    #[test]
    fn factory_panic_is_reported_as_worker_panic() {
        match spawn_worker::<ErrorBackend, _>(config(1, Duration::from_secs(1)), || {
            panic!("fixture factory panic")
        }) {
            Err(error) => assert_eq!(error, SymbolizeError::WorkerPanic),
            Ok(_) => panic!("backend factory panic must abort spawn"),
        }
    }

    #[test]
    fn cloned_clients_keep_concurrent_replies_correlated() {
        const CLIENTS: u64 = 24;

        let (client, handle) = spawn_worker(config(32, Duration::from_secs(2)), || {
            Ok(EchoBackend {
                _thread_owned: Rc::new(()),
            })
        })
        .unwrap();
        let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));
        let mut callers = Vec::new();

        for addr in 0..CLIENTS {
            let client = client.clone();
            let barrier = Arc::clone(&barrier);
            callers.push(thread::spawn(move || {
                barrier.wait();
                (addr, client.symbolize(addr))
            }));
        }
        barrier.wait();

        for caller in callers {
            let (addr, result) = caller.join().unwrap();
            assert_eq!(result.unwrap().name, format!("frame_{addr}+0x0"));
        }
        handle.shutdown().unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn kernel_worker_is_unavailable_off_linux() {
        match spawn_kernel_symbolizer(SymbolizerWorkerConfig::default()) {
            Err(error) => assert_eq!(error, SymbolizeError::NoSymbolFile),
            Ok(_) => panic!("kernel symbolizer must not start off Linux"),
        }
    }
}
