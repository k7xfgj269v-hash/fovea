//! Level 0 introspection use case.
//!
//! The use case depends only on proc, symbolizer, and clock ports. Linux
//! filesystem access is isolated in [`crate::proc_source::LinuxProcSource`].

use std::sync::Arc;
use std::time::Duration;

use introspect_schema::{
    ConfidenceSummary, CostHint, Handles, Hotspot, Identity, Level0, LowConfidenceField, ProcState,
    RecentEvents, Resource, RunState, StackFrame, SymbolConfidence, Symbolized,
};

#[cfg(target_os = "linux")]
use crate::proc_source::ThreadSampleClock;
use crate::proc_source::{CpuCounters, ProcError, ProcSnapshot, ProcSource, SampleClock};
use crate::proc_view::{self, Stat, CMDLINE_SHORT_MAX, MEM_SHAPE_TOP_N};
#[cfg(any(test, target_os = "linux"))]
use crate::symbolize::FallbackSymbolizer;
use crate::symbolize::Symbolizer;

pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Level 0 orchestration over injectable ports.
pub struct IntrospectService {
    source: Arc<dyn ProcSource>,
    symbolizer: Arc<dyn Symbolizer>,
    clock: Arc<dyn SampleClock>,
    sample_interval: Duration,
}

impl IntrospectService {
    pub fn new(
        source: Arc<dyn ProcSource>,
        symbolizer: Arc<dyn Symbolizer>,
        clock: Arc<dyn SampleClock>,
        sample_interval: Duration,
    ) -> Self {
        Self {
            source,
            symbolizer,
            clock,
            sample_interval,
        }
    }

    pub fn introspect(&self, pid: i32) -> Result<Level0, ProcError> {
        validate_requested_pid(pid)?;
        introspect_from_ports(
            self.source.as_ref(),
            self.symbolizer.as_ref(),
            self.clock.as_ref(),
            self.sample_interval,
            pid,
        )
    }
}

/// Compatibility entry point. It only assembles platform adapters.
pub fn introspect(pid: i32) -> Result<Level0, ProcError> {
    validate_requested_pid(pid)?;

    #[cfg(target_os = "linux")]
    {
        use crate::proc_source::LinuxProcSource;

        IntrospectService::new(
            Arc::new(LinuxProcSource::new()),
            Arc::new(FallbackSymbolizer),
            Arc::new(ThreadSampleClock),
            DEFAULT_SAMPLE_INTERVAL,
        )
        .introspect(pid);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err(ProcError::UnsupportedPlatform)
    }
}

/// Compatibility helper for callers that inject only a symbolizer.
pub fn introspect_with(pid: i32, symbolizer: &dyn Symbolizer) -> Result<Level0, ProcError> {
    validate_requested_pid(pid)?;

    #[cfg(target_os = "linux")]
    {
        use crate::proc_source::LinuxProcSource;

        let source = LinuxProcSource::new();
        let clock = ThreadSampleClock;
        introspect_from_ports(&source, symbolizer, &clock, DEFAULT_SAMPLE_INTERVAL, pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, symbolizer);
        Err(ProcError::UnsupportedPlatform)
    }
}

fn introspect_from_ports(
    source: &dyn ProcSource,
    symbolizer: &dyn Symbolizer,
    clock: &dyn SampleClock,
    sample_interval: Duration,
    pid: i32,
) -> Result<Level0, ProcError> {
    validate_requested_pid(pid)?;
    let snapshot = source.snapshot(pid)?;
    validate_page_size(snapshot.page_size_bytes)?;
    let stat = proc_view::parse_stat(&snapshot.stat)?;
    validate_snapshot_pid(pid, stat.pid)?;

    let start = CpuCounters {
        process_ticks: stat.process_ticks,
        system_ticks: snapshot.system_cpu_ticks,
        process_start_time_ticks: stat.process_start_time_ticks,
    };
    let cpu_sample = sample_cpu(
        source,
        clock,
        sample_interval,
        pid,
        start,
        snapshot.logical_cpus,
    )?;

    build_level0(pid, &snapshot, stat, cpu_sample, symbolizer)
}

fn validate_requested_pid(pid: i32) -> Result<(), ProcError> {
    if pid < 1 {
        return Err(ProcError::InvalidPid { pid });
    }
    Ok(())
}

fn validate_page_size(page_size_bytes: u64) -> Result<(), ProcError> {
    if page_size_bytes == 0 {
        return Err(ProcError::InvalidPageSize);
    }
    Ok(())
}

fn validate_snapshot_pid(requested_pid: i32, observed_pid: i32) -> Result<(), ProcError> {
    if requested_pid == observed_pid {
        return Ok(());
    }
    Err(ProcError::Parse {
        what: "stat.pid".into(),
        reason: format!("请求 pid {requested_pid}，stat 返回 pid {observed_pid}"),
    })
}

#[derive(Debug)]
struct CpuSample {
    pct_cpu: f32,
    low_confidence_reason: Option<String>,
}

impl CpuSample {
    fn valid(pct_cpu: f32) -> Self {
        Self {
            pct_cpu,
            low_confidence_reason: None,
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            pct_cpu: 0.0,
            low_confidence_reason: Some(reason.into()),
        }
    }
}

fn sample_cpu(
    source: &dyn ProcSource,
    clock: &dyn SampleClock,
    sample_interval: Duration,
    pid: i32,
    start: CpuCounters,
    logical_cpus: u32,
) -> Result<CpuSample, ProcError> {
    clock.sleep(sample_interval);
    let end = match source.cpu_counters(pid) {
        Ok(counters) => counters,
        Err(error @ ProcError::ProcNotFound { .. }) => return Err(error),
        Err(_) => return Err(ProcError::CpuSampleFailed),
    };
    if end.process_start_time_ticks != start.process_start_time_ticks {
        return Err(ProcError::ProcNotFound { pid });
    }

    Ok(calculate_cpu_percent(start, end, logical_cpus))
}

fn calculate_cpu_percent(start: CpuCounters, end: CpuCounters, logical_cpus: u32) -> CpuSample {
    let Some(process_delta) = end.process_ticks.checked_sub(start.process_ticks) else {
        return CpuSample::unavailable("CPU 短采样进程计数器回退");
    };
    let Some(system_delta) = end.system_ticks.checked_sub(start.system_ticks) else {
        return CpuSample::unavailable("CPU 短采样系统计数器回退");
    };
    if system_delta == 0 {
        return CpuSample::unavailable("CPU 短采样系统计数器增量为 0");
    }
    if logical_cpus == 0 {
        return CpuSample::unavailable("CPU 短采样 logical_cpus 不可用");
    }

    let pct_cpu = process_delta as f64 / system_delta as f64 * logical_cpus as f64 * 100.0;
    if !pct_cpu.is_finite() {
        return CpuSample::unavailable("CPU 短采样结果不是有限数");
    }

    CpuSample::valid(pct_cpu as f32)
}

fn build_level0(
    pid: i32,
    snapshot: &ProcSnapshot,
    stat: Stat,
    cpu_sample: CpuSample,
    symbolizer: &dyn Symbolizer,
) -> Result<Level0, ProcError> {
    let status = proc_view::parse_status(&snapshot.status)?;
    let mem_shape = proc_view::parse_maps(&snapshot.maps)?;
    let nr_fds = proc_view::scan_fds_from_names(&snapshot.fd_names);
    let wchan_raw = snapshot
        .wchan
        .as_deref()
        .and_then(proc_view::read_wchan_from_str);
    let kernel_stack = snapshot
        .kernel_stack
        .as_deref()
        .map(proc_view::read_kernel_stack_from_str)
        .unwrap_or_default();

    let identity = Identity {
        pid,
        comm: stat.comm.clone(),
        exe: snapshot.exe.clone(),
        cmdline: build_cmdline(&snapshot.cmdline),
        uid: status.uid,
        cgroup: snapshot.cgroup.clone(),
    };

    let wchan = wchan_raw.as_ref().map(|name| Symbolized {
        name: name.clone(),
        source: SymbolConfidence::Kallsyms,
    });
    let run_state = stat.state;
    let state = ProcState {
        run_state,
        last_cpu: stat.last_cpu,
        nr_threads: stat.nr_threads,
        wchan,
    };

    let resource = Resource {
        rss_bytes: stat.rss.saturating_mul(snapshot.page_size_bytes),
        vsz_bytes: stat.vsize,
        nr_fds,
        pct_cpu: cpu_sample.pct_cpu,
        ctxt_switches: introspect_schema::CtxtSwitches {
            voluntary: status.voluntary_ctxt_switches,
            nonvoluntary: status.nonvoluntary_ctxt_switches,
        },
    };

    let hotspot = build_hotspot(run_state, &kernel_stack, symbolizer);
    let mut confidence = build_confidence(&wchan_raw, &hotspot, symbolizer);
    if let Some(reason) = cpu_sample.low_confidence_reason {
        merge_low_confidence_field(
            &mut confidence.low_fields,
            "resource.pct_cpu".into(),
            SymbolConfidence::None,
            reason,
        );
    }

    Ok(Level0 {
        identity,
        state,
        resource,
        mem_shape,
        hotspot,
        recent: RecentEvents::RecorderOff,
        confidence,
        handles: Handles::default(),
        cost_hint: CostHint {
            token: 500,
            api_cost: None,
            overhead_est_ns: 0,
        },
    })
}

/// Pure compatibility helper used by portable parser/domain tests.
#[allow(clippy::too_many_arguments)]
pub fn introspect_with_inputs(
    pid: i32,
    stat_s: &str,
    status_s: &str,
    maps_s: &str,
    wchan_s: &str,
    cmdline_bytes: &[u8],
    fd_names: &[String],
    stack_s: &str,
    symbolizer: &dyn Symbolizer,
) -> Result<Level0, ProcError> {
    validate_requested_pid(pid)?;
    let snapshot = ProcSnapshot {
        stat: stat_s.to_string(),
        status: status_s.to_string(),
        maps: maps_s.to_string(),
        wchan: Some(wchan_s.to_string()),
        cmdline: cmdline_bytes.to_vec(),
        fd_names: fd_names.to_vec(),
        kernel_stack: Some(stack_s.to_string()),
        exe: None,
        cgroup: None,
        system_cpu_ticks: 0,
        logical_cpus: 1,
        page_size_bytes: 4096,
    };
    let stat = proc_view::parse_stat(stat_s)?;
    validate_snapshot_pid(pid, stat.pid)?;
    build_level0(pid, &snapshot, stat, CpuSample::valid(0.0), symbolizer)
}

fn build_cmdline(bytes: &[u8]) -> introspect_schema::Cmdline {
    let joined = String::from_utf8_lossy(bytes)
        .replace('\u{0}', " ")
        .trim()
        .to_string();
    let full_len = joined.len();
    let mut chars = joined.chars();
    let mut short: String = chars.by_ref().take(CMDLINE_SHORT_MAX).collect();
    if chars.next().is_some() {
        short.push('…');
    }
    introspect_schema::Cmdline { short, full_len }
}

fn build_hotspot(
    run_state: RunState,
    kernel_stack: &[(String, String)],
    symbolizer: &dyn Symbolizer,
) -> Hotspot {
    if run_state != RunState::D || kernel_stack.is_empty() {
        return Hotspot::NotBlocked;
    }

    let take_n = MEM_SHAPE_TOP_N.min(kernel_stack.len());
    let mut frames = Vec::with_capacity(take_n);
    for (idx, (addr_s, _raw_symbol)) in kernel_stack.iter().take(take_n).enumerate() {
        let addr = u64::from_str_radix(addr_s.trim_start_matches("0x"), 16).unwrap_or(0);
        let (symbol, confidence) = match symbolizer.symbolize(addr) {
            Ok(symbol) => {
                let confidence = symbol.source;
                (Some(symbol), Some(confidence))
            }
            Err(_) => (None, None),
        };
        frames.push(StackFrame {
            idx: idx as u32,
            addr: addr_s.clone(),
            symbol,
            confidence,
        });
    }
    Hotspot::Blocked { frames }
}

fn build_confidence(
    wchan_raw: &Option<String>,
    hotspot: &Hotspot,
    symbolizer: &dyn Symbolizer,
) -> ConfidenceSummary {
    let mut low_fields = Vec::new();
    let mut symbol_scores = Vec::new();

    if let Hotspot::Blocked { frames } = hotspot {
        for frame in frames {
            let confidence = frame_symbol_confidence(frame);
            symbol_scores.push(confidence.score());
            if confidence == SymbolConfidence::None {
                merge_low_confidence_field(
                    &mut low_fields,
                    format!("hotspot.frames[{}].symbol", frame.idx),
                    SymbolConfidence::None,
                    "blocked frame symbolization failed or produced no confidence".into(),
                );
            }
        }
    }

    let mut cross_check_failed = false;
    let top_frame = match hotspot {
        Hotspot::Blocked { frames } => frames.first(),
        Hotspot::NotBlocked => None,
    };
    if let (Some(wchan_name), Some(top_frame)) = (wchan_raw, top_frame) {
        let top_addr =
            u64::from_str_radix(top_frame.addr.trim_start_matches("0x"), 16).unwrap_or(0);
        if let Some(reason) = symbolizer.cross_check(top_addr, wchan_name) {
            cross_check_failed = true;
            merge_low_confidence_field(
                &mut low_fields,
                "state.wchan".into(),
                SymbolConfidence::Kallsyms,
                reason.clone(),
            );
            merge_low_confidence_field(
                &mut low_fields,
                format!("hotspot.frames[{}].symbol", top_frame.idx),
                frame_symbol_confidence(top_frame),
                format!("wchan/top frame cross-check failed: {reason}"),
            );
        }
    }

    let mut overall = if symbol_scores.is_empty() {
        1.0
    } else {
        symbol_scores.iter().sum::<f32>() / symbol_scores.len() as f32
    };
    if cross_check_failed {
        overall = overall.min(0.5);
    }

    ConfidenceSummary {
        overall,
        low_fields,
    }
}

fn frame_symbol_confidence(frame: &StackFrame) -> SymbolConfidence {
    match (&frame.symbol, frame.confidence) {
        (Some(_), Some(confidence)) => confidence,
        _ => SymbolConfidence::None,
    }
}

fn merge_low_confidence_field(
    low_fields: &mut Vec<LowConfidenceField>,
    path: String,
    confidence: SymbolConfidence,
    reason: String,
) {
    if let Some(existing) = low_fields.iter_mut().find(|field| field.path == path) {
        let merged_confidence = match existing.confidence {
            Some(current) if current.score() <= confidence.score() => current,
            _ => confidence,
        };
        existing.confidence = Some(merged_confidence);
        if existing.reason != reason {
            existing.reason.push_str("; ");
            existing.reason.push_str(&reason);
        }
        return;
    }

    low_fields.push(LowConfidenceField {
        path,
        confidence: Some(confidence),
        reason,
    });
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::symbolize::{make_symbolized, SymbolizeError};
    use introspect_schema::MapKind;

    const TEST_PROCESS_START_TIME_TICKS: u64 = 12_345;

    #[allow(clippy::too_many_arguments)]
    fn stat_line(
        pid: i32,
        comm: &str,
        state: &str,
        utime: u64,
        stime: u64,
        nr_threads: u32,
        vsize: u64,
        rss: u64,
        last_cpu: u32,
    ) -> String {
        let mut fields = vec!["0".to_string(); 39];
        fields[0] = state.to_string();
        fields[11] = utime.to_string();
        fields[12] = stime.to_string();
        fields[17] = nr_threads.to_string();
        fields[19] = TEST_PROCESS_START_TIME_TICKS.to_string();
        fields[20] = vsize.to_string();
        fields[21] = rss.to_string();
        fields[36] = last_cpu.to_string();
        format!("{pid} ({comm}) {}\n", fields.join(" "))
    }

    fn cpu_counters(process_ticks: u64, system_ticks: u64) -> CpuCounters {
        CpuCounters {
            process_ticks,
            system_ticks,
            process_start_time_ticks: TEST_PROCESS_START_TIME_TICKS,
        }
    }

    fn base_snapshot(stat: String) -> ProcSnapshot {
        ProcSnapshot {
            stat,
            status: "Uid:\t1000\t1000\t1000\t1000\n\
                     voluntary_ctxt_switches:\t3\n\
                     nonvoluntary_ctxt_switches:\t17\n"
                .into(),
            maps: "".into(),
            wchan: None,
            cmdline: b"./demo\0--foo\0".to_vec(),
            fd_names: vec!["0".into(), "1".into(), "2".into()],
            kernel_stack: None,
            exe: Some("/usr/bin/demo".into()),
            cgroup: Some("/user.slice/demo.scope".into()),
            system_cpu_ticks: 1_000,
            logical_cpus: 4,
            page_size_bytes: 4096,
        }
    }

    struct MockProcSource {
        snapshot: ProcSnapshot,
        cpu_samples: Mutex<VecDeque<Result<CpuCounters, ProcError>>>,
    }

    impl MockProcSource {
        fn new(
            snapshot: ProcSnapshot,
            cpu_samples: impl IntoIterator<Item = Result<CpuCounters, ProcError>>,
        ) -> Self {
            Self {
                snapshot,
                cpu_samples: Mutex::new(cpu_samples.into_iter().collect()),
            }
        }
    }

    impl ProcSource for MockProcSource {
        fn snapshot(&self, _pid: i32) -> Result<ProcSnapshot, ProcError> {
            Ok(self.snapshot.clone())
        }

        fn cpu_counters(&self, _pid: i32) -> Result<CpuCounters, ProcError> {
            self.cpu_samples
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must provide a CPU sample")
        }
    }

    #[derive(Default)]
    struct RecordingClock {
        sleeps: Mutex<Vec<Duration>>,
    }

    impl SampleClock for RecordingClock {
        fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
        }
    }

    fn service(
        source: Arc<dyn ProcSource>,
        clock: Arc<dyn SampleClock>,
        interval: Duration,
    ) -> IntrospectService {
        IntrospectService::new(source, Arc::new(FallbackSymbolizer), clock, interval)
    }

    struct PermissionSnapshotSource;

    impl ProcSource for PermissionSnapshotSource {
        fn snapshot(&self, _pid: i32) -> Result<ProcSnapshot, ProcError> {
            Err(ProcError::Permission)
        }

        fn cpu_counters(&self, _pid: i32) -> Result<CpuCounters, ProcError> {
            panic!("CPU sampling must not run after snapshot failure")
        }
    }

    #[test]
    fn contract_complete_fake_snapshot_populates_level0_without_live_procfs() {
        let mut snapshot = base_snapshot(stat_line(42, "demo", "D", 100, 50, 2, 4_000_000, 25, 3));
        snapshot.maps = "7f0000000000-7f0000100000 rw-p 00000000 00:00 0 [heap]\n".into();
        snapshot.wchan = Some("futex_wait_queue_me\n".into());
        snapshot.cmdline = b"/usr/bin/demo\0--mode\0contract\0".to_vec();
        snapshot.fd_names = vec![".".into(), "..".into(), "0".into(), "1".into()];
        snapshot.kernel_stack = Some("[<0000000000000001>] futex_wait_queue_me+0x1/0x2\n".into());
        let source = Arc::new(MockProcSource::new(
            snapshot,
            [Ok(cpu_counters(160, 1_100))],
        ));
        let clock = Arc::new(RecordingClock::default());
        let interval = Duration::from_millis(9);

        let level0 = service(source, clock.clone(), interval)
            .introspect(42)
            .expect("complete fake snapshot must assemble Level0");

        assert_eq!(level0.identity.pid, 42);
        assert_eq!(level0.identity.comm, "demo");
        assert_eq!(level0.identity.exe.as_deref(), Some("/usr/bin/demo"));
        assert_eq!(
            level0.identity.cgroup.as_deref(),
            Some("/user.slice/demo.scope")
        );
        assert_eq!(
            level0.identity.cmdline.short,
            "/usr/bin/demo --mode contract"
        );
        assert_eq!(level0.identity.uid, 1000);
        assert_eq!(level0.state.run_state, RunState::D);
        assert_eq!(level0.state.nr_threads, 2);
        assert_eq!(level0.state.last_cpu, 3);
        assert_eq!(level0.state.wchan.unwrap().name, "futex_wait_queue_me");
        assert_eq!(level0.resource.rss_bytes, 25 * 4096);
        assert_eq!(level0.resource.vsz_bytes, 4_000_000);
        assert_eq!(level0.resource.nr_fds, 2);
        assert!((level0.resource.pct_cpu - 40.0).abs() < f32::EPSILON);
        assert_eq!(level0.resource.ctxt_switches.voluntary, 3);
        assert_eq!(level0.resource.ctxt_switches.nonvoluntary, 17);
        assert_eq!(level0.mem_shape.histogram.len(), 1);
        assert!(matches!(
            level0.hotspot,
            Hotspot::Blocked { ref frames } if frames.len() == 1
        ));
        assert_eq!(*clock.sleeps.lock().unwrap(), [interval]);
    }

    #[test]
    fn contract_runtime_page_sizes_and_saturating_rss_boundary() {
        let inspect = |rss_pages: u64, page_size_bytes: u64| {
            let mut snapshot =
                base_snapshot(stat_line(42, "demo", "S", 0, 0, 1, 4096, rss_pages, 0));
            snapshot.page_size_bytes = page_size_bytes;
            let source = Arc::new(MockProcSource::new(snapshot, [Ok(cpu_counters(0, 1_001))]));
            service(source, Arc::new(RecordingClock::default()), Duration::ZERO)
                .introspect(42)
                .unwrap()
                .resource
                .rss_bytes
        };

        assert_eq!(inspect(7, 4096), 7 * 4096);
        assert_eq!(inspect(7, 65_536), 7 * 65_536);

        let page_size = 65_536;
        let largest_non_saturating = u64::MAX / page_size;
        assert_eq!(
            inspect(largest_non_saturating, page_size),
            largest_non_saturating * page_size
        );
        assert_eq!(inspect(largest_non_saturating + 1, page_size), u64::MAX);
    }

    #[test]
    fn contract_cpu_zero_normal_and_multicore_above_100_percent() {
        for (end, logical_cpus, expected) in [
            (cpu_counters(100, 1_100), 4, 0.0),
            (cpu_counters(120, 1_200), 4, 40.0),
            (cpu_counters(180, 1_100), 4, 320.0),
        ] {
            let sample = calculate_cpu_percent(cpu_counters(100, 1_000), end, logical_cpus);

            assert!(sample.low_confidence_reason.is_none());
            assert!(sample.pct_cpu.is_finite());
            assert!((sample.pct_cpu - expected).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn contract_required_snapshot_permission_is_structured_and_skips_sampling() {
        let clock = Arc::new(RecordingClock::default());
        let error = service(
            Arc::new(PermissionSnapshotSource),
            clock.clone(),
            Duration::from_millis(10),
        )
        .introspect(42)
        .expect_err("required snapshot permission failure must be fatal");

        assert_eq!(error, ProcError::Permission);
        let (kind, reason, next_step) = error.to_error_report();
        assert_eq!(kind, "proc_permission_denied");
        assert!(reason.contains("权限"));
        assert!(next_step.is_some());
        assert!(clock.sleeps.lock().unwrap().is_empty());
    }

    #[test]
    fn contract_second_sample_source_failures_are_distinct_and_fatal() {
        for source_error in [
            ProcError::Permission,
            ProcError::Read {
                what: "/private/host/path".into(),
                reason: "secret detail".into(),
            },
            ProcError::Parse {
                what: "stat.utime".into(),
                reason: "not a number".into(),
            },
        ] {
            let snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
            let source = Arc::new(MockProcSource::new(snapshot, [Err(source_error)]));
            let error = service(
                source,
                Arc::new(RecordingClock::default()),
                Duration::from_millis(1),
            )
            .introspect(42)
            .expect_err("CPU source failures must abort introspection");

            assert_eq!(error, ProcError::CpuSampleFailed);
            let (kind, reason, next_step) = error.to_error_report();
            assert_eq!(kind, "proc_cpu_sample_failed");
            assert!(!reason.contains("/private/host/path"));
            assert!(!reason.contains("secret detail"));
            assert!(next_step.is_some());
        }
    }

    #[test]
    fn contract_concurrent_services_keep_fake_sources_and_clocks_independent() {
        let mut snapshot_a = base_snapshot(stat_line(101, "alpha", "S", 10, 10, 1, 4096, 2, 0));
        snapshot_a.exe = Some("/usr/bin/alpha".into());
        snapshot_a.cgroup = Some("/alpha.scope".into());
        snapshot_a.logical_cpus = 2;
        let source_a = Arc::new(MockProcSource::new(
            snapshot_a,
            [Ok(cpu_counters(30, 1_100))],
        ));
        let clock_a = Arc::new(RecordingClock::default());
        let interval_a = Duration::from_millis(3);
        let service_a = service(source_a, clock_a.clone(), interval_a);

        let mut snapshot_b = base_snapshot(stat_line(202, "beta", "S", 150, 50, 1, 8192, 3, 1));
        snapshot_b.exe = Some("/opt/beta".into());
        snapshot_b.cgroup = Some("/beta.scope".into());
        snapshot_b.system_cpu_ticks = 5_000;
        snapshot_b.logical_cpus = 4;
        snapshot_b.page_size_bytes = 65_536;
        let source_b = Arc::new(MockProcSource::new(
            snapshot_b,
            [Ok(cpu_counters(260, 5_100))],
        ));
        let clock_b = Arc::new(RecordingClock::default());
        let interval_b = Duration::from_millis(7);
        let service_b = service(source_b, clock_b.clone(), interval_b);

        let alpha = std::thread::spawn(move || service_a.introspect(101).unwrap());
        let beta = std::thread::spawn(move || service_b.introspect(202).unwrap());
        let alpha = alpha.join().unwrap();
        let beta = beta.join().unwrap();

        assert_eq!(alpha.identity.comm, "alpha");
        assert_eq!(alpha.identity.exe.as_deref(), Some("/usr/bin/alpha"));
        assert_eq!(alpha.identity.cgroup.as_deref(), Some("/alpha.scope"));
        assert_eq!(alpha.resource.rss_bytes, 2 * 4096);
        assert!((alpha.resource.pct_cpu - 20.0).abs() < f32::EPSILON);

        assert_eq!(beta.identity.comm, "beta");
        assert_eq!(beta.identity.exe.as_deref(), Some("/opt/beta"));
        assert_eq!(beta.identity.cgroup.as_deref(), Some("/beta.scope"));
        assert_eq!(beta.resource.rss_bytes, 3 * 65_536);
        assert!((beta.resource.pct_cpu - 240.0).abs() < f32::EPSILON);

        assert_eq!(*clock_a.sleeps.lock().unwrap(), [interval_a]);
        assert_eq!(*clock_b.sleeps.lock().unwrap(), [interval_b]);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn compatibility_entries_report_unsupported_platform_off_linux() {
        assert!(matches!(
            introspect(0),
            Err(ProcError::InvalidPid { pid: 0 })
        ));
        assert!(matches!(introspect(1), Err(ProcError::UnsupportedPlatform)));
        assert!(matches!(
            introspect_with(1, &FallbackSymbolizer),
            Err(ProcError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn introspect_with_inputs_builds_level0() {
        let stat = stat_line(42, "demo", "D", 0, 0, 7, 4_000_000, 100_000, 9);
        let status = "Name:\tdemo\n\
                      Uid:\t1000\t1000\t1000\t1000\n\
                      FDSize:\t64\n\
                      voluntary_ctxt_switches:\t3\n\
                      nonvoluntary_ctxt_switches:\t17\n";
        let maps = "\
7f0000000000-7f0000100000 rw-p 00000000 00:00 0                          [heap]\n\
7ffe00000000-7ffe00004000 rw-p 00000000 00:00 0                          [stack]\n\
7f0020001000-7f0020005000 r-xp 00001000 08:01 1234  /usr/lib/libc.so.6\n\
7f002000d000-7f0020010000 rw-p 00005000 08:01 9999  /var/data/cache.db\n";
        let wchan = "futex_wait_queue_me\n";
        let cmdline: &[u8] = b"./demo\0--foo\0--bar\0";
        let fds = vec![".".into(), "..".into(), "0".into(), "1".into(), "2".into()];
        let stack = "[<ffffffff81a2b3c4>] futex_wait_queue_me+0xabc/0x123\n\
                     [<ffffffff81a2b4d0>] __schedule+0x1a2/0x345\n";

        let level0 = introspect_with_inputs(
            42,
            &stat,
            status,
            maps,
            wchan,
            cmdline,
            &fds,
            stack,
            &FallbackSymbolizer,
        )
        .expect("portable inputs must assemble Level0");

        assert_eq!(level0.identity.pid, 42);
        assert_eq!(level0.identity.comm, "demo");
        assert_eq!(level0.identity.uid, 1000);
        assert_eq!(level0.identity.cmdline.full_len, 18);
        assert_eq!(level0.state.run_state, RunState::D);
        assert_eq!(level0.state.nr_threads, 7);
        assert_eq!(level0.state.last_cpu, 9);
        assert!(level0
            .state
            .wchan
            .as_ref()
            .unwrap()
            .name
            .contains("futex_wait"));
        assert_eq!(level0.resource.rss_bytes, 100_000 * 4096);
        assert_eq!(level0.resource.vsz_bytes, 4_000_000);
        assert_eq!(level0.resource.nr_fds, 3);
        assert_eq!(level0.resource.ctxt_switches.voluntary, 3);
        assert_eq!(level0.resource.ctxt_switches.nonvoluntary, 17);
        assert!(level0.mem_shape.histogram.len() <= 5);
        assert!(level0.mem_shape.top_n.len() <= MEM_SHAPE_TOP_N);
        assert!(level0
            .mem_shape
            .histogram
            .iter()
            .any(|bucket| bucket.kind == MapKind::Heap));
        assert!(level0
            .mem_shape
            .histogram
            .iter()
            .any(|bucket| bucket.kind == MapKind::XLib));
        assert!(matches!(level0.hotspot, Hotspot::Blocked { .. }));
        assert!(matches!(level0.recent, RecentEvents::RecorderOff));
        assert!(level0.handles.threads.is_none());
        assert_eq!(level0.cost_hint.token, 500);
        assert!(level0.cost_hint.api_cost.is_none());
        assert_eq!(level0.cost_hint.overhead_est_ns, 0);
    }

    #[test]
    fn service_uses_runtime_page_size_identity_and_scaled_cpu_delta() {
        let mut snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4_000_000, 25, 3));
        snapshot.page_size_bytes = 16_384;
        let source = Arc::new(MockProcSource::new(
            snapshot,
            [Ok(cpu_counters(170, 1_200))],
        ));
        let clock = Arc::new(RecordingClock::default());
        let interval = Duration::from_millis(25);

        let level0 = service(source, clock.clone(), interval)
            .introspect(42)
            .expect("valid short sample must succeed");

        assert_eq!(level0.identity.exe.as_deref(), Some("/usr/bin/demo"));
        assert_eq!(
            level0.identity.cgroup.as_deref(),
            Some("/user.slice/demo.scope")
        );
        assert_eq!(level0.resource.rss_bytes, 25 * 16_384);
        assert!((level0.resource.pct_cpu - 40.0).abs() < f32::EPSILON);
        assert!(!level0
            .confidence
            .low_fields
            .iter()
            .any(|field| field.path == "resource.pct_cpu"));
        assert_eq!(*clock.sleeps.lock().unwrap(), [interval]);
    }

    fn assert_low_cpu_sample(
        end: Result<CpuCounters, ProcError>,
        logical_cpus: u32,
        expected_reason: &str,
    ) {
        let mut snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
        snapshot.logical_cpus = logical_cpus;
        let source = Arc::new(MockProcSource::new(snapshot, [end]));
        let level0 = service(
            source,
            Arc::new(RecordingClock::default()),
            Duration::from_millis(1),
        )
        .introspect(42)
        .expect("unavailable CPU samples are non-fatal");

        assert_eq!(level0.resource.pct_cpu, 0.0);
        assert!(level0.resource.pct_cpu.is_finite());
        let fields: Vec<_> = level0
            .confidence
            .low_fields
            .iter()
            .filter(|field| field.path == "resource.pct_cpu")
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].confidence, Some(SymbolConfidence::None));
        assert!(fields[0].reason.contains(expected_reason));
    }

    #[test]
    fn counter_rollbacks_zero_delta_and_invalid_cpu_count_are_low_confidence() {
        assert_low_cpu_sample(Ok(cpu_counters(149, 1_200)), 4, "进程计数器回退");
        assert_low_cpu_sample(Ok(cpu_counters(170, 999)), 4, "系统计数器回退");
        assert_low_cpu_sample(Ok(cpu_counters(170, 1_000)), 4, "增量为 0");
        assert_low_cpu_sample(Ok(cpu_counters(170, 1_200)), 0, "logical_cpus");
    }

    #[test]
    fn process_disappearance_during_cpu_sample_is_fatal() {
        let snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
        let source = Arc::new(MockProcSource::new(
            snapshot,
            [Err(ProcError::ProcNotFound { pid: 42 })],
        ));
        let error = service(
            source,
            Arc::new(RecordingClock::default()),
            Duration::from_millis(1),
        )
        .introspect(42)
        .expect_err("process disappearance must abort introspection");
        assert_eq!(error, ProcError::ProcNotFound { pid: 42 });
    }

    #[test]
    fn pid_generation_mismatch_is_fatal_even_with_monotonic_counters() {
        let snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
        let source = Arc::new(MockProcSource::new(
            snapshot,
            [Ok(CpuCounters {
                process_ticks: 170,
                system_ticks: 1_200,
                process_start_time_ticks: TEST_PROCESS_START_TIME_TICKS + 1,
            })],
        ));

        let error = service(
            source,
            Arc::new(RecordingClock::default()),
            Duration::from_millis(1),
        )
        .introspect(42)
        .expect_err("PID generation reuse must abort introspection");

        assert_eq!(error, ProcError::ProcNotFound { pid: 42 });
    }

    #[test]
    fn matching_generation_preserves_cpu_percent() {
        let snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
        let source = Arc::new(MockProcSource::new(
            snapshot,
            [Ok(cpu_counters(170, 1_200))],
        ));

        let level0 = service(
            source,
            Arc::new(RecordingClock::default()),
            Duration::from_millis(1),
        )
        .introspect(42)
        .expect("matching PID generation must preserve CPU sampling");

        assert!((level0.resource.pct_cpu - 40.0).abs() < f32::EPSILON);
    }

    struct PanicProcSource;

    impl ProcSource for PanicProcSource {
        fn snapshot(&self, _pid: i32) -> Result<ProcSnapshot, ProcError> {
            panic!("invalid pid must be rejected before ProcSource::snapshot")
        }

        fn cpu_counters(&self, _pid: i32) -> Result<CpuCounters, ProcError> {
            panic!("invalid pid must be rejected before ProcSource::cpu_counters")
        }
    }

    #[test]
    fn invalid_pid_is_rejected_before_proc_source_is_called() {
        for pid in [0, -1, i32::MIN] {
            let error = service(
                Arc::new(PanicProcSource),
                Arc::new(RecordingClock::default()),
                Duration::ZERO,
            )
            .introspect(pid)
            .expect_err("pid below one must be rejected");

            assert_eq!(error, ProcError::InvalidPid { pid });
            let (kind, reason, next_step) = error.to_error_report();
            assert_eq!(kind, "proc_invalid_pid");
            assert!(reason.contains(&pid.to_string()));
            assert!(next_step.is_some());
        }
    }

    #[test]
    fn zero_page_size_is_rejected_before_cpu_sampling() {
        let mut snapshot = base_snapshot(stat_line(42, "demo", "S", 100, 50, 2, 4096, 1, 0));
        snapshot.page_size_bytes = 0;
        let clock = Arc::new(RecordingClock::default());
        let error = service(
            Arc::new(MockProcSource::new(snapshot, [])),
            clock.clone(),
            Duration::from_millis(1),
        )
        .introspect(42)
        .expect_err("zero page size must not be accepted");

        assert_eq!(error, ProcError::InvalidPageSize);
        let (kind, _, next_step) = error.to_error_report();
        assert_eq!(kind, "proc_invalid_page_size");
        assert!(next_step.is_some());
        assert!(clock.sleeps.lock().unwrap().is_empty());
    }

    #[test]
    fn rss_conversion_saturates_at_u64_max() {
        let mut snapshot = base_snapshot(stat_line(42, "demo", "S", 0, 0, 1, 4096, u64::MAX, 0));
        snapshot.page_size_bytes = 2;
        let source = Arc::new(MockProcSource::new(snapshot, [Ok(cpu_counters(0, 1_001))]));

        let level0 = service(source, Arc::new(RecordingClock::default()), Duration::ZERO)
            .introspect(42)
            .unwrap();
        assert_eq!(level0.resource.rss_bytes, u64::MAX);
    }

    #[test]
    fn resource_context_switches_ignore_stat_rt_priority_and_policy() {
        let mut fields = vec!["0"; 39];
        fields[0] = "S";
        fields[17] = "1";
        fields[20] = "4096";
        fields[21] = "1";
        fields[36] = "2";
        fields[37] = "900";
        fields[38] = "901";
        let stat = format!("7 (scheduler-fields) {}\n", fields.join(" "));
        let status = "Uid:\t1000\t1000\t1000\t1000\n\
                      voluntary_ctxt_switches:\t12\n\
                      nonvoluntary_ctxt_switches:\t34\n";

        let level0 = introspect_with_inputs(
            7,
            &stat,
            status,
            "",
            "",
            b"scheduler-fields\0",
            &[],
            "",
            &FallbackSymbolizer,
        )
        .expect("valid stat and status fixtures must build Level0");

        assert_eq!(level0.resource.ctxt_switches.voluntary, 12);
        assert_eq!(level0.resource.ctxt_switches.nonvoluntary, 34);
        assert_ne!(level0.resource.ctxt_switches.voluntary, 900);
        assert_ne!(level0.resource.ctxt_switches.nonvoluntary, 901);
    }

    #[test]
    fn cmdline_preserves_255_256_and_257_unicode_scalar_boundaries() {
        for scalar_count in [255, 256, 257] {
            let joined = "界".repeat(scalar_count);
            let cmdline = build_cmdline(joined.as_bytes());
            let expected_short = if scalar_count > CMDLINE_SHORT_MAX {
                format!("{}…", "界".repeat(CMDLINE_SHORT_MAX))
            } else {
                joined.clone()
            };

            assert_eq!(cmdline.short, expected_short);
            assert_eq!(cmdline.full_len, joined.len());
            assert_eq!(
                cmdline.short.chars().count(),
                scalar_count.min(CMDLINE_SHORT_MAX) + usize::from(scalar_count > CMDLINE_SHORT_MAX)
            );
        }
    }

    #[test]
    fn cmdline_multibyte_character_crossing_byte_256_stays_valid_utf8() {
        let joined = format!("{}éz", "a".repeat(255));
        let cmdline = build_cmdline(joined.as_bytes());
        let expected = format!("{}é…", "a".repeat(255));

        assert_eq!(cmdline.full_len, 258);
        assert_eq!(cmdline.short.chars().count(), 257);
        assert_eq!(cmdline.short, expected);
    }

    struct SuccessfulSymbolizer;

    impl Symbolizer for SuccessfulSymbolizer {
        fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            let confidence = if addr == 1 {
                SymbolConfidence::Dwarf
            } else {
                SymbolConfidence::Kallsyms
            };
            Ok(make_symbolized(format!("frame_{addr}"), confidence))
        }
    }

    #[test]
    fn confidence_averages_successful_frame_symbols() {
        let stack = vec![
            ("1".to_string(), "frame_1".to_string()),
            ("2".to_string(), "frame_2".to_string()),
        ];
        let symbolizer = SuccessfulSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &symbolizer);
        let confidence = build_confidence(&None, &hotspot, &symbolizer);

        assert!((confidence.overall - 0.875).abs() < f32::EPSILON);
        assert!(confidence.low_fields.is_empty());
    }

    struct PartiallyFailingSymbolizer;

    impl Symbolizer for PartiallyFailingSymbolizer {
        fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            if addr == 1 {
                Ok(make_symbolized("frame_1", SymbolConfidence::Dwarf))
            } else {
                Err(SymbolizeError::NotFound {
                    addr: format!("{addr:#x}"),
                })
            }
        }
    }

    #[test]
    fn failed_blocked_frame_symbols_lower_overall_confidence() {
        let stack = vec![
            ("1".to_string(), "frame_1".to_string()),
            ("2".to_string(), "frame_2".to_string()),
            ("3".to_string(), "frame_3".to_string()),
        ];
        let symbolizer = PartiallyFailingSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &symbolizer);
        let confidence = build_confidence(&None, &hotspot, &symbolizer);

        assert!((confidence.overall - (1.0 / 3.0)).abs() < f32::EPSILON);
        assert!(confidence.overall < SymbolConfidence::Dwarf.score());
        assert_eq!(confidence.low_fields.len(), 2);
        for (idx, field) in confidence.low_fields.iter().enumerate() {
            assert_eq!(field.path, format!("hotspot.frames[{}].symbol", idx + 1));
            assert_eq!(field.confidence, Some(SymbolConfidence::None));
        }
    }

    struct CrossCheckFailureSymbolizer;

    impl Symbolizer for CrossCheckFailureSymbolizer {
        fn symbolize(&self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
            Ok(make_symbolized("frame", SymbolConfidence::Dwarf))
        }

        fn cross_check(&self, _addr: u64, _expected_top_frame: &str) -> Option<String> {
            Some("wchan/top frame mismatch".into())
        }
    }

    #[test]
    fn failed_cross_check_caps_overall_confidence() {
        let stack = vec![("1".to_string(), "frame".to_string())];
        let symbolizer = CrossCheckFailureSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &symbolizer);
        let confidence = build_confidence(&Some("wchan".into()), &hotspot, &symbolizer);

        assert_eq!(confidence.overall, 0.5);
        let paths: Vec<_> = confidence
            .low_fields
            .iter()
            .map(|field| field.path.as_str())
            .collect();
        assert_eq!(paths, ["state.wchan", "hotspot.frames[0].symbol"]);
        assert_eq!(
            confidence.low_fields[1].confidence,
            Some(SymbolConfidence::Dwarf)
        );
    }

    struct SymbolizationAndCrossCheckFailureSymbolizer;

    impl Symbolizer for SymbolizationAndCrossCheckFailureSymbolizer {
        fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            Err(SymbolizeError::NotFound {
                addr: format!("{addr:#x}"),
            })
        }

        fn cross_check(&self, _addr: u64, _expected_top_frame: &str) -> Option<String> {
            Some("wchan/top frame mismatch".into())
        }
    }

    #[test]
    fn failed_top_symbol_and_cross_check_merge_confidence_evidence() {
        let stack = vec![("1".to_string(), "frame".to_string())];
        let symbolizer = SymbolizationAndCrossCheckFailureSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &symbolizer);
        let confidence = build_confidence(&Some("wchan".into()), &hotspot, &symbolizer);

        assert_eq!(confidence.overall, 0.0);
        let top_fields: Vec<_> = confidence
            .low_fields
            .iter()
            .filter(|field| field.path == "hotspot.frames[0].symbol")
            .collect();
        assert_eq!(top_fields.len(), 1);
        assert_eq!(top_fields[0].confidence, Some(SymbolConfidence::None));
        assert!(top_fields[0].reason.contains("symbolization failed"));
        assert!(top_fields[0].reason.contains("wchan/top frame mismatch"));
    }

    #[test]
    fn proc_error_to_error_report_shape() {
        let error = ProcError::ProcNotFound { pid: 999 };
        let (kind, reason, next_step) = error.to_error_report();
        assert_eq!(kind, "proc_not_found");
        assert!(reason.contains("999"));
        assert!(next_step.is_some());
    }

    #[test]
    fn proc_error_reports_do_not_echo_internal_paths_or_reasons() {
        for error in [
            ProcError::Read {
                what: "/Users/private/project/secret".into(),
                reason: "username and dependency version".into(),
            },
            ProcError::Parse {
                what: "/Users/private/project/secret".into(),
                reason: "username and dependency version".into(),
            },
        ] {
            let (_, reason, next_step) = error.to_error_report();
            assert!(!reason.contains("/Users/private/project/secret"));
            assert!(!reason.contains("username and dependency version"));
            assert!(next_step.is_some());
        }
    }

    #[test]
    fn new_proc_error_variants_are_structured_and_serializable() {
        for error in [
            ProcError::InvalidPid { pid: 0 },
            ProcError::UnsupportedPlatform,
            ProcError::InvalidPageSize,
            ProcError::CpuSampleFailed,
        ] {
            let encoded = serde_json::to_string(&error).expect("ProcError must serialize");
            let decoded: ProcError =
                serde_json::from_str(&encoded).expect("ProcError must deserialize");
            assert_eq!(decoded, error);
        }
    }
}
