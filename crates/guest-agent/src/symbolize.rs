//! 符号化 + 回溯（§4.2 / §13.1）。

use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{
    self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
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

#[derive(Clone)]
pub struct SymbolizerWorkerClient {
    requests: SyncSender<SymbolizeRequest>,
    request_timeout: Duration,
}

impl Symbolizer for SymbolizerWorkerClient {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        let (reply, response) = mpsc::sync_channel(1);
        match self.requests.try_send(SymbolizeRequest { addr, reply }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(SymbolizeError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                return Err(SymbolizeError::WorkerStopped)
            }
        }

        match response.recv_timeout(self.request_timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(SymbolizeError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(SymbolizeError::WorkerStopped),
        }
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
}

impl SymbolizerWorkerHandle {
    pub fn shutdown(mut self) -> Result<(), SymbolizeError> {
        let signal_result = self.shutdown.send(());
        let join = self.join.take().ok_or(SymbolizeError::WorkerStopped)?;
        match join.join() {
            Ok(()) if signal_result.is_ok() => Ok(()),
            Ok(()) => Err(SymbolizeError::WorkerStopped),
            Err(_) => Err(SymbolizeError::WorkerPanic),
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
        spawn_worker::<UnavailableKernelBackend, _>(config, || {
            Err(SymbolizeError::NoSymbolFile)
        })
    }
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

    let join = thread::Builder::new()
        .name("fovea-symbolizer".into())
        .spawn(move || {
            let mut backend = match catch_unwind(AssertUnwindSafe(factory)) {
                Ok(Ok(backend)) => backend,
                Ok(Err(error)) => {
                    let _ = initialized.send(Err(error));
                    return;
                }
                Err(payload) => {
                    drop(initialized);
                    std::panic::resume_unwind(payload);
                }
            };
            if initialized.send(Ok(())).is_err() {
                return;
            }
            worker_loop(&mut backend, request_rx, shutdown_rx);
        })
        .map_err(|error| SymbolizeError::Backend {
            reason: error.to_string(),
        })?;

    match initialized_rx.recv() {
        Ok(Ok(())) => Ok((
            SymbolizerWorkerClient {
                requests,
                request_timeout: config.request_timeout,
            },
            SymbolizerWorkerHandle {
                shutdown,
                join: Some(join),
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
) {
    loop {
        match shutdown.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }

        match requests.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(request) => {
                let result =
                    catch_unwind(AssertUnwindSafe(|| backend.symbolize(request.addr)));
                match result {
                    Ok(result) => {
                        let _ = request.reply.send(result);
                    }
                    Err(payload) => {
                        let _ = request.reply.send(Err(SymbolizeError::WorkerPanic));
                        std::panic::resume_unwind(payload);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
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
            .symbolize_single(
                &self.source,
                blazesym::symbolize::Input::AbsAddr(addr),
            )
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
            source: blaze_confidence(&symbol),
        }),
        blazesym::symbolize::Symbolized::Unknown(
            blazesym::symbolize::Reason::MissingSyms,
        ) => Err(SymbolizeError::NoSymbolFile),
        blazesym::symbolize::Symbolized::Unknown(_) => {
            Err(SymbolizeError::NotFound {
                addr: format!("{addr:#x}"),
            })
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn blaze_confidence(
    symbol: &blazesym::symbolize::Sym<'_>,
) -> introspect_schema::SymbolConfidence {
    use introspect_schema::SymbolConfidence;

    if symbol.code_info.is_some() {
        SymbolConfidence::Dwarf
    } else if symbol.size.is_some() {
        SymbolConfidence::Dynsym
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
        let _symbolize_single = || {
            symbolizer.symbolize_single(
                &source,
                blazesym::symbolize::Input::AbsAddr(0_u64),
            )
        };

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
        let converted = blaze_to_symbolized(
            blazesym::symbolize::Symbolized::Sym(symbol),
            0x1020,
        )
        .unwrap();
        assert_eq!(converted.name, "schedule+0x20");
        assert_eq!(converted.source, SymbolConfidence::Kallsyms);

        let error = blaze_to_symbolized(
            blazesym::symbolize::Symbolized::Unknown(
                blazesym::symbolize::Reason::MissingSyms,
            ),
            0x1020,
        )
        .unwrap_err();
        assert_eq!(error, SymbolizeError::NoSymbolFile);
        let error = blaze_to_symbolized(
            blazesym::symbolize::Symbolized::Unknown(
                blazesym::symbolize::Reason::UnknownAddr,
            ),
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
        let (client, handle) = spawn_worker(
            config(4, Duration::from_secs(1)),
            || {
                Ok(EchoBackend {
                    _thread_owned: Rc::new(()),
                })
            },
        )
        .unwrap();

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
                1 => Err(SymbolizeError::NotFound {
                    addr: "0x1".into(),
                }),
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
            spawn_worker(config(4, Duration::from_secs(1)), || Ok(ErrorBackend))
                .unwrap();

        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::NotFound {
                addr: "0x1".into()
            }
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
        let (client, handle) = spawn_worker(
            config(2, Duration::from_secs(1)),
            move || {
                Ok(BlockingBackend {
                    entered,
                    release: release_rx,
                })
            },
        )
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
        assert_eq!(
            client.symbolize(4).unwrap_err(),
            SymbolizeError::QueueFull
        );

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
    fn request_timeout_is_distinct() {
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (client, handle) = spawn_worker(
            config(1, Duration::from_millis(20)),
            move || {
                Ok(BlockingBackend {
                    entered,
                    release: release_rx,
                })
            },
        )
        .unwrap();

        let caller = thread::spawn(move || client.symbolize(1));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            caller.join().unwrap().unwrap_err(),
            SymbolizeError::Timeout
        );
        release.send(()).unwrap();
        handle.shutdown().unwrap();
    }

    #[test]
    fn clean_shutdown_stops_future_requests() {
        let (client, handle) = spawn_worker(
            config(2, Duration::from_secs(1)),
            || {
                Ok(EchoBackend {
                    _thread_owned: Rc::new(()),
                })
            },
        )
        .unwrap();

        handle.shutdown().unwrap();
        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::WorkerStopped
        );
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
            spawn_worker(config(1, Duration::from_secs(1)), || Ok(PanicBackend))
                .unwrap();

        assert_eq!(
            client.symbolize(1).unwrap_err(),
            SymbolizeError::WorkerPanic
        );
        assert_eq!(handle.shutdown(), Err(SymbolizeError::WorkerPanic));
    }

    #[test]
    fn initialization_failure_is_returned() {
        match spawn_worker::<ErrorBackend, _>(
            config(1, Duration::from_secs(1)),
            || Err(SymbolizeError::NoSymbolFile),
        ) {
            Err(error) => assert_eq!(error, SymbolizeError::NoSymbolFile),
            Ok(_) => panic!("backend initialization failure must abort spawn"),
        }
    }

    #[test]
    fn cloned_clients_keep_concurrent_replies_correlated() {
        const CLIENTS: u64 = 24;

        let (client, handle) = spawn_worker(
            config(32, Duration::from_secs(2)),
            || {
                Ok(EchoBackend {
                    _thread_owned: Rc::new(()),
                })
            },
        )
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
