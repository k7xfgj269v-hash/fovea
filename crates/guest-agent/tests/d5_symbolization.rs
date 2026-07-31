mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::d7_fixtures::{fixture_bytes, fixture_text, stat_fixture};
use guest_agent::introspect::{
    assemble_default_introspection, estimate_level0_tokens, kernel_introspection_symbolizer_worker,
    IntrospectionSymbolizerWorker,
};
use guest_agent::proc_view::{parse_stat, read_kernel_stack_from_str};
use guest_agent::schema::{Hotspot, LowConfidenceField, SymbolConfidence, Symbolized};
use guest_agent::symbolize::{
    spawn_injected_symbolizer_worker, spawn_injected_symbolizer_worker_with_shutdown_probe,
    SymbolizeError, Symbolizer, SymbolizerWorkerConfig,
};
use guest_agent::{
    introspect_with_inputs, CpuCounters, ProcError, ProcSnapshot, ProcSource, SampleClock,
};

const BACKEND_FAILURE: &str = "fixture backend unavailable";
const SENTINEL_PREFIX: &str = "sentinel-worker";

#[derive(Clone)]
struct FixtureSource {
    snapshot: ProcSnapshot,
    end: CpuCounters,
}

impl ProcSource for FixtureSource {
    fn snapshot(&self, _pid: i32) -> Result<ProcSnapshot, ProcError> {
        Ok(self.snapshot.clone())
    }

    fn cpu_counters(&self, _pid: i32) -> Result<CpuCounters, ProcError> {
        Ok(self.end)
    }
}

struct AdvancingClock {
    now: Mutex<Instant>,
}

impl AdvancingClock {
    fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
        }
    }
}

impl SampleClock for AdvancingClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) {
        *self.now.lock().unwrap() += duration;
    }
}

struct DwarfSymbolizer;

impl Symbolizer for DwarfSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        Ok(Symbolized {
            name: format!("resolved_{addr:x}"),
            source: SymbolConfidence::Dwarf,
        })
    }
}

struct SentinelSymbolizer {
    calls: Arc<AtomicUsize>,
}

impl Symbolizer for SentinelSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Symbolized {
            name: format!("{SENTINEL_PREFIX}-{addr:016x}"),
            source: SymbolConfidence::Dwarf,
        })
    }
}

struct BackendFailureSymbolizer;

impl Symbolizer for BackendFailureSymbolizer {
    fn symbolize(&self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
        Err(SymbolizeError::Backend {
            reason: BACKEND_FAILURE.into(),
        })
    }
}

struct InjectedWorker {
    symbolizer: Arc<dyn Symbolizer>,
    shutdown_error: Option<SymbolizeError>,
}

impl IntrospectionSymbolizerWorker for InjectedWorker {
    fn symbolizer(&self) -> &dyn Symbolizer {
        self.symbolizer.as_ref()
    }

    fn shutdown(self: Box<Self>) -> Result<(), SymbolizeError> {
        match self.shutdown_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct BlockingSymbolizer {
    entered: Mutex<Option<mpsc::Sender<()>>>,
    released: Arc<(Mutex<bool>, Condvar)>,
    finished: mpsc::Sender<()>,
}

impl Symbolizer for BlockingSymbolizer {
    fn symbolize(&self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }

        let (released, changed) = self.released.as_ref();
        let mut is_released = released.lock().unwrap();
        while !*is_released {
            is_released = changed.wait(is_released).unwrap();
        }

        let _ = self.finished.send(());
        Ok(Symbolized {
            name: "released-blocking-symbolizer".into(),
            source: SymbolConfidence::Dwarf,
        })
    }
}

fn captured_d_stat() -> String {
    String::from_utf8(stat_fixture('D')).expect("captured D-state stat must be UTF-8")
}

fn captured_fixture_ports() -> (i32, Arc<FixtureSource>, Arc<AdvancingClock>) {
    let stat = captured_d_stat();
    let parsed = parse_stat(&stat).expect("captured D-state stat must parse");
    let source = FixtureSource {
        snapshot: ProcSnapshot {
            stat,
            status: fixture_text("level0/status"),
            maps: fixture_text("level0/maps"),
            wchan: Some(fixture_text("level0/wchan")),
            cmdline: fixture_bytes("level0/cmdline"),
            nr_fds: 3,
            kernel_stack: Some(fixture_text("level0/stack")),
            exe: Some(fixture_text("level0/exe").trim_end().to_owned()),
            cgroup: Some(fixture_text("level0/cgroup").trim_end().to_owned()),
            degradations: Vec::new(),
            system_cpu_ticks: 100,
            logical_cpus: 1,
            page_size_bytes: 4096,
        },
        end: CpuCounters {
            process_ticks: parsed.process_ticks + 1,
            system_ticks: 101,
            process_start_time_ticks: parsed.process_start_time_ticks,
        },
    };
    (
        parsed.pid,
        Arc::new(source),
        Arc::new(AdvancingClock::new()),
    )
}

fn assemble_fixture<F>(spawn_worker: F) -> guest_agent::schema::Level0
where
    F: FnOnce() -> Result<Box<dyn IntrospectionSymbolizerWorker>, SymbolizeError>,
{
    let (pid, source, clock) = captured_fixture_ports();
    assemble_default_introspection(pid, source, clock, Duration::ZERO, spawn_worker)
        .expect("captured proc inputs must assemble")
}

fn assemble_with_sentinel(
    shutdown_error: Option<SymbolizeError>,
) -> (guest_agent::schema::Level0, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let symbolizer: Arc<dyn Symbolizer> = Arc::new(SentinelSymbolizer {
        calls: Arc::clone(&calls),
    });
    let level0 = assemble_fixture(move || {
        Ok(Box::new(InjectedWorker {
            symbolizer,
            shutdown_error,
        }))
    });
    (level0, calls)
}

fn captured_level0(wchan: &str, symbolizer: &dyn Symbolizer) -> guest_agent::schema::Level0 {
    let stat = captured_d_stat();
    let pid = parse_stat(&stat)
        .expect("captured D-state stat must parse")
        .pid;

    introspect_with_inputs(
        pid,
        &stat,
        &fixture_text("level0/status"),
        &fixture_text("level0/maps"),
        wchan,
        &fixture_bytes("level0/cmdline"),
        &[],
        &fixture_text("level0/stack"),
        symbolizer,
    )
    .expect("captured proc inputs must assemble")
}

fn blocked_frames(level0: &guest_agent::schema::Level0) -> &[guest_agent::schema::StackFrame] {
    match &level0.hotspot {
        Hotspot::Blocked { frames } => frames,
        Hotspot::NotBlocked => panic!("captured D-state fixture must produce blocked frames"),
    }
}

fn low_fields_at<'a>(fields: &'a [LowConfidenceField], path: &str) -> Vec<&'a LowConfidenceField> {
    fields.iter().filter(|field| field.path == path).collect()
}

#[test]
fn successful_default_assembly_uses_real_worker_and_retains_client_through_shutdown() {
    let raw_stack = read_kernel_stack_from_str(&fixture_text("level0/stack"));
    let calls = Arc::new(AtomicUsize::new(0));
    let symbolizer: Arc<dyn Symbolizer> = Arc::new(SentinelSymbolizer {
        calls: Arc::clone(&calls),
    });
    let (shutdown_probe, shutdown_observed) = mpsc::channel();
    let level0 = assemble_fixture(move || {
        let (client, handle) = spawn_injected_symbolizer_worker_with_shutdown_probe(
            SymbolizerWorkerConfig {
                queue_capacity: 1,
                request_timeout: Duration::from_secs(1),
            },
            symbolizer,
            shutdown_probe,
        )?;
        Ok(kernel_introspection_symbolizer_worker(client, handle))
    });
    let frames = blocked_frames(&level0);

    assert_eq!(
        shutdown_observed
            .recv_timeout(Duration::from_secs(1))
            .expect("real worker shutdown must report client liveness"),
        1,
        "exactly the supplied client must still be alive when handle shutdown begins"
    );
    assert_eq!(frames.len(), raw_stack.len());
    assert_eq!(calls.load(Ordering::SeqCst), frames.len());
    for (idx, (frame, (raw_addr, raw_name))) in frames.iter().zip(raw_stack.iter()).enumerate() {
        let addr = u64::from_str_radix(raw_addr.trim_start_matches("0x"), 16)
            .expect("captured stack address must be hexadecimal");
        let symbol = frame
            .symbol
            .as_ref()
            .unwrap_or_else(|| panic!("worker frame {idx} must have a symbol"));
        assert_eq!(symbol.name, format!("{SENTINEL_PREFIX}-{addr:016x}"));
        assert_ne!(&symbol.name, raw_name);
        assert_eq!(symbol.source, SymbolConfidence::Dwarf);
        assert_eq!(frame.confidence, Some(SymbolConfidence::Dwarf));
        assert!(low_fields_at(
            &level0.confidence.low_fields,
            &format!("hotspot.frames[{idx}].symbol")
        )
        .is_empty());
    }
    assert!(low_fields_at(&level0.confidence.low_fields, "hotspot.frames").is_empty());
    assert!(level0
        .confidence
        .low_fields
        .iter()
        .all(|field| !field.reason.contains("symbolizer_shutdown_error_kind=")));
    assert_eq!(level0.confidence.overall, 1.0);
    assert_eq!(level0.cost_hint.token, estimate_level0_tokens(&level0));
}

#[test]
fn initialization_failure_is_the_only_default_assembly_fallback_path() {
    let (clean, clean_calls) = assemble_with_sentinel(None);
    let init_error = SymbolizeError::NoSymbolFile;
    let degraded = assemble_fixture(|| Err(init_error.clone()));
    let raw_stack = read_kernel_stack_from_str(&fixture_text("level0/stack"));

    assert_eq!(clean_calls.load(Ordering::SeqCst), raw_stack.len());
    assert!(blocked_frames(&clean).iter().all(|frame| {
        frame
            .symbol
            .as_ref()
            .is_some_and(|symbol| symbol.name.starts_with(SENTINEL_PREFIX))
    }));
    for (frame, (_, raw_name)) in blocked_frames(&degraded).iter().zip(raw_stack.iter()) {
        let symbol = frame
            .symbol
            .as_ref()
            .expect("initialization fallback must retain raw Kallsyms");
        assert_eq!(&symbol.name, raw_name);
        assert_eq!(symbol.source, SymbolConfidence::Kallsyms);
        assert_eq!(frame.confidence, Some(SymbolConfidence::Kallsyms));
    }

    let evidence = low_fields_at(&degraded.confidence.low_fields, "hotspot.frames");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].confidence, Some(SymbolConfidence::None));
    assert_eq!(
        evidence[0].reason,
        format!(
            "symbolizer_init_error_kind={}; fallback=raw_kallsyms; detail={init_error}",
            init_error.kind()
        )
    );
    assert!(degraded.confidence.overall < clean.confidence.overall);
    assert_eq!(
        degraded.cost_hint.token,
        estimate_level0_tokens(&degraded),
        "token estimate must describe the final payload after init degradation"
    );
}

#[test]
fn shutdown_failure_is_observable_and_recalculates_confidence_and_token() {
    let (clean, _) = assemble_with_sentinel(None);
    let shutdown_error = SymbolizeError::ShutdownTimeout;
    let (degraded, calls) = assemble_with_sentinel(Some(shutdown_error.clone()));
    let frames = blocked_frames(&degraded);

    assert_eq!(calls.load(Ordering::SeqCst), frames.len());
    assert!(frames.iter().all(|frame| {
        frame
            .symbol
            .as_ref()
            .is_some_and(|symbol| symbol.name.starts_with(SENTINEL_PREFIX))
    }));
    assert!(frames.iter().enumerate().all(|(idx, _)| low_fields_at(
        &degraded.confidence.low_fields,
        &format!("hotspot.frames[{idx}].symbol")
    )
    .is_empty()));

    let evidence = low_fields_at(&degraded.confidence.low_fields, "hotspot.frames");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].confidence, Some(SymbolConfidence::None));
    assert_eq!(
        evidence[0].reason,
        format!(
            "symbolizer_shutdown_error_kind={}; worker_shutdown=failed; detail={shutdown_error}",
            shutdown_error.kind()
        )
    );
    assert!(degraded.confidence.overall < clean.confidence.overall);
    assert_eq!(
        degraded.cost_hint.token,
        estimate_level0_tokens(&degraded),
        "token estimate must describe the final payload after shutdown degradation"
    );
}

#[test]
fn blocking_worker_request_and_shutdown_both_timeout_within_finite_bounds() {
    let timeout = Duration::from_millis(50);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let symbolizer: Arc<dyn Symbolizer> = Arc::new(BlockingSymbolizer {
        entered: Mutex::new(Some(entered_tx)),
        released: Arc::clone(&released),
        finished: finished_tx,
    });
    let (client, handle) = spawn_injected_symbolizer_worker(
        SymbolizerWorkerConfig {
            queue_capacity: 1,
            request_timeout: timeout,
        },
        symbolizer,
    )
    .expect("injected blocking worker must start");

    let caller = thread::spawn(move || {
        let started = Instant::now();
        let result = client.symbolize(0x1234);
        (result, started.elapsed())
    });
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking backend must receive the request");
    let (request_result, request_elapsed) =
        caller.join().expect("symbolizer caller must not panic");

    let shutdown_started = Instant::now();
    let shutdown_result = handle.shutdown();
    let shutdown_elapsed = shutdown_started.elapsed();

    let (is_released, changed) = released.as_ref();
    *is_released.lock().unwrap() = true;
    changed.notify_all();
    finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking backend must exit after release");

    assert!(matches!(request_result, Err(SymbolizeError::Timeout)));
    assert_eq!(shutdown_result, Err(SymbolizeError::ShutdownTimeout));
    for (name, elapsed) in [("request", request_elapsed), ("shutdown", shutdown_elapsed)] {
        assert!(
            elapsed + Duration::from_millis(5) >= timeout,
            "{name} returned before its configured timeout: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "{name} exceeded the finite acceptance bound: {elapsed:?}"
        );
    }
}

#[test]
fn each_failed_address_retains_raw_kallsyms_with_exact_evidence() {
    let stack_text = fixture_text("level0/stack");
    let raw_stack = read_kernel_stack_from_str(&stack_text);
    assert!(
        raw_stack.len() >= 3,
        "captured kernel stack must exercise multiple frame paths"
    );

    let level0 = captured_level0(&fixture_text("level0/wchan"), &BackendFailureSymbolizer);
    let frames = blocked_frames(&level0);
    assert_eq!(frames.len(), raw_stack.len());

    let expected_error = SymbolizeError::Backend {
        reason: BACKEND_FAILURE.into(),
    };
    let expected_reason = format!(
        "symbolizer failed: error_kind={}; fallback=raw_kallsyms; retained raw kernel Kallsyms symbol; detail={expected_error}",
        expected_error.kind()
    );

    for (idx, (frame, (raw_addr, raw_name))) in frames.iter().zip(raw_stack.iter()).enumerate() {
        assert_eq!(&frame.addr, raw_addr);
        let symbol = frame
            .symbol
            .as_ref()
            .unwrap_or_else(|| panic!("frame {idx} must retain its raw symbol"));
        assert_eq!(&symbol.name, raw_name);
        assert_eq!(symbol.source, SymbolConfidence::Kallsyms);
        assert_eq!(frame.confidence, Some(SymbolConfidence::Kallsyms));

        let path = format!("hotspot.frames[{idx}].symbol");
        let evidence = low_fields_at(&level0.confidence.low_fields, &path);
        assert_eq!(
            evidence.len(),
            1,
            "frame {idx} must have exactly one merged low_fields entry"
        );
        assert_eq!(evidence[0].confidence, Some(SymbolConfidence::Kallsyms));
        assert_eq!(evidence[0].reason, expected_reason);
    }

    let clean = captured_level0(&fixture_text("level0/wchan"), &DwarfSymbolizer);
    assert!(
        clean
            .confidence
            .low_fields
            .iter()
            .all(|field| !field.path.starts_with("hotspot.frames[")),
        "successful symbolization must not emit constant per-frame degradation"
    );
    assert!(level0.confidence.overall < clean.confidence.overall);
}

#[test]
fn wchan_cross_check_reports_only_real_name_mismatches() {
    let stack_text = fixture_text("level0/stack");
    let raw_stack = read_kernel_stack_from_str(&stack_text);
    let captured_wchan = fixture_text("level0/wchan");
    assert_eq!(
        captured_wchan.trim().split('+').next(),
        raw_stack[0].1.trim().split('+').next(),
        "captured wchan and top stack frame must be a real matching pair"
    );

    let matching = captured_level0(&captured_wchan, &DwarfSymbolizer);
    assert!(low_fields_at(&matching.confidence.low_fields, "state.wchan").is_empty());
    assert!(
        low_fields_at(&matching.confidence.low_fields, "hotspot.frames[0].symbol").is_empty(),
        "matching names must not produce a constant top-frame alarm"
    );

    let different_captured_name = raw_stack
        .iter()
        .skip(1)
        .map(|(_, name)| name.as_str())
        .find(|name| name.split('+').next() != captured_wchan.trim().split('+').next())
        .expect("captured stack must contain a name different from wchan");
    let mismatching = captured_level0(different_captured_name, &DwarfSymbolizer);
    let wchan_evidence = low_fields_at(&mismatching.confidence.low_fields, "state.wchan");
    let frame_evidence = low_fields_at(
        &mismatching.confidence.low_fields,
        "hotspot.frames[0].symbol",
    );

    assert_eq!(wchan_evidence.len(), 1);
    assert_eq!(frame_evidence.len(), 1);
    assert!(wchan_evidence[0]
        .reason
        .contains("wchan/top frame mismatch"));
    assert!(frame_evidence[0]
        .reason
        .contains("wchan/top frame mismatch"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux CI with readable nonzero /proc/kallsyms"]
fn live_kernel_worker_matches_two_distinct_nonzero_kallsyms_names() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use guest_agent::symbolize::{spawn_kernel_symbolizer, FallbackSymbolizer};

    let kallsyms = fs::read_to_string("/proc/kallsyms")
        .expect("D5 live prerequisite failed: /proc/kallsyms must be readable");
    let mut names_by_address = BTreeMap::<u64, BTreeSet<String>>::new();
    for line in kallsyms.lines() {
        let mut fields = line.split_whitespace();
        let Some(addr) = fields
            .next()
            .and_then(|value| u64::from_str_radix(value, 16).ok())
        else {
            continue;
        };
        let Some(kind) = fields
            .next()
            .and_then(|value| value.as_bytes().first().copied())
        else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        if addr != 0 && matches!(kind, b't' | b'T' | b'w' | b'W') {
            names_by_address
                .entry(addr)
                .or_default()
                .insert(name.to_owned());
        }
    }
    let candidates = names_by_address.into_iter().take(4096).collect::<Vec<_>>();
    assert!(
        candidates.len() >= 2,
        "D5 live prerequisite failed: /proc/kallsyms exposed fewer than two distinct nonzero text-symbol addresses; check kptr_restrict and CI privileges"
    );

    let (client, handle) = spawn_kernel_symbolizer(SymbolizerWorkerConfig::default())
        .expect("D5 live prerequisite failed: kernel blazesym worker must start");
    let mut resolved = Vec::new();
    let mut failures = Vec::new();
    for (addr, raw_names) in &candidates {
        match client.symbolize(*addr) {
            Ok(symbol) => {
                let normalized = symbol
                    .name
                    .trim()
                    .split('+')
                    .next()
                    .unwrap_or(symbol.name.trim())
                    .to_owned();
                if raw_names.contains(&normalized)
                    && resolved
                        .iter()
                        .all(|(_, prior_name, _): &(u64, String, Symbolized)| {
                            prior_name != &normalized
                        })
                {
                    resolved.push((*addr, normalized, symbol));
                    if resolved.len() == 2 {
                        break;
                    }
                }
            }
            Err(error) if failures.len() < 8 => {
                failures.push(format!("{addr:#x} {raw_names:?}: {error}"));
            }
            Err(_) => {}
        }
    }
    handle
        .shutdown()
        .expect("kernel symbolizer worker must shut down cleanly");

    assert!(
        resolved.len() >= 2,
        "D5 live acceptance failed: blazesym did not exactly resolve two distinct nonzero kallsyms names from {} candidates; sample failures={failures:?}",
        candidates.len()
    );
    for (addr, raw_name, symbol) in &resolved {
        let normalized = symbol.name.trim().split('+').next().unwrap();
        assert_eq!(normalized, raw_name);
        assert_ne!(symbol.source, SymbolConfidence::None);
        assert!(matches!(
            FallbackSymbolizer.symbolize(*addr),
            Err(SymbolizeError::NotFound { .. })
        ));
    }
    assert_ne!(resolved[0].0, resolved[1].0);
    assert_ne!(resolved[0].1, resolved[1].1);
    assert_ne!(resolved[0].2.name, resolved[1].2.name);
}
