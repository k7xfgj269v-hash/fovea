mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::d7_fixtures::{fixture_bytes, fixture_text};
use guest_agent::proc_view::parse_stat;
use guest_agent::schema::{Hotspot, LowConfidenceField, SymbolConfidence, Symbolized};
use guest_agent::symbolize::{SymbolizeError, Symbolizer};
use guest_agent::{
    introspect_with_inputs, CpuCounters, IntrospectService, ProcDegradation, ProcError,
    ProcSnapshot, ProcSource, SampleClock,
};

const FIXTURE_PID: i32 = 208_288;

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
        let mut now = self.now.lock().unwrap();
        *now += duration;
    }
}

struct DwarfSymbolizer;

impl Symbolizer for DwarfSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        Ok(Symbolized {
            name: format!("dwarf_{addr:x}"),
            source: SymbolConfidence::Dwarf,
        })
    }
}

fn captured_d_stat() -> String {
    let mut stat = fixture_bytes("level0/stat");
    let state_offset = stat
        .windows(3)
        .position(|window| window[0] == b')' && window[1] == b' ' && window[2] == b'S')
        .expect("captured sleep stat must contain the S state byte")
        + 2;
    stat[state_offset] = b'D';
    String::from_utf8(stat).expect("captured stat must remain UTF-8")
}

fn captured_s_stat() -> String {
    String::from_utf8(fixture_bytes("level0/stat")).expect("captured stat must be UTF-8")
}

fn captured_status_without_context_switches() -> String {
    fixture_text("level0/status")
        .lines()
        .filter(|line| {
            !line.starts_with("voluntary_ctxt_switches:")
                && !line.starts_with("nonvoluntary_ctxt_switches:")
        })
        .map(|line| format!("{line}\n"))
        .collect()
}

fn fixture_snapshot(
    stat: String,
    status: String,
    wchan: Option<String>,
    cgroup: Option<String>,
    exe: Option<String>,
    kernel_stack: Option<String>,
    degradations: Vec<ProcDegradation>,
) -> (i32, ProcSnapshot, CpuCounters) {
    let parsed = parse_stat(&stat).expect("fixture stat must parse");
    let end = CpuCounters {
        process_ticks: parsed.process_ticks + 1,
        system_ticks: 101,
        process_start_time_ticks: parsed.process_start_time_ticks,
    };
    let snapshot = ProcSnapshot {
        stat,
        status,
        maps: fixture_text("level0/maps"),
        wchan,
        cmdline: fixture_bytes("level0/cmdline"),
        nr_fds: 3,
        kernel_stack,
        exe,
        cgroup,
        degradations,
        system_cpu_ticks: 100,
        logical_cpus: 1,
        page_size_bytes: 4096,
    };
    (parsed.pid, snapshot, end)
}

fn complete_d_snapshot() -> (i32, ProcSnapshot, CpuCounters) {
    fixture_snapshot(
        captured_d_stat(),
        fixture_text("level0/status"),
        Some(fixture_text("level0/wchan")),
        Some(fixture_text("level0/cgroup").trim_end().to_owned()),
        Some(fixture_text("level0/exe").trim_end().to_owned()),
        Some(fixture_text("level0/stack")),
        Vec::new(),
    )
}

fn run_fixture(
    pid: i32,
    snapshot: ProcSnapshot,
    end: CpuCounters,
    symbolizer: Arc<dyn Symbolizer>,
    interval: Duration,
) -> guest_agent::schema::Level0 {
    IntrospectService::new(
        Arc::new(FixtureSource { snapshot, end }),
        symbolizer,
        Arc::new(AdvancingClock::new()),
        interval,
    )
    .introspect(pid)
    .expect("fixture Level0 must assemble")
}

fn has_path(fields: &[LowConfidenceField], path: &str) -> bool {
    fields.iter().any(|field| field.path == path)
}

#[test]
fn b2_missing_non_symbol_fields_are_reported_and_lower_overall() {
    let (pid, snapshot, end) = fixture_snapshot(
        captured_s_stat(),
        captured_status_without_context_switches(),
        None,
        None,
        None,
        None,
        Vec::new(),
    );
    let level0 = run_fixture(
        pid,
        snapshot,
        end,
        Arc::new(DwarfSymbolizer),
        Duration::ZERO,
    );

    assert!(level0.confidence.overall < 1.0);
    for path in [
        "state.wchan",
        "resource.ctxt_switches",
        "identity.cgroup",
        "identity.exe",
    ] {
        assert!(
            has_path(&level0.confidence.low_fields, path),
            "missing evidence for {path}: {:?}",
            level0.confidence.low_fields
        );
    }
}

#[test]
fn b2_complete_dwarf_fixture_is_exactly_fully_confident() {
    let (pid, snapshot, end) = complete_d_snapshot();
    let level0 = run_fixture(
        pid,
        snapshot,
        end,
        Arc::new(DwarfSymbolizer),
        Duration::ZERO,
    );

    assert_eq!(level0.confidence.overall, 1.0);
    assert!(level0.confidence.low_fields.is_empty());
}

#[test]
fn b2_zero_two_four_degradations_are_strictly_decreasing() {
    let (pid, complete, end) = complete_d_snapshot();
    let none = run_fixture(
        pid,
        complete.clone(),
        end,
        Arc::new(DwarfSymbolizer),
        Duration::ZERO,
    );

    let mut two = complete.clone();
    two.cgroup = None;
    two.exe = None;
    let two = run_fixture(pid, two, end, Arc::new(DwarfSymbolizer), Duration::ZERO);

    let mut four = complete;
    four.cgroup = None;
    four.exe = None;
    four.wchan = None;
    four.status = captured_status_without_context_switches();
    let four = run_fixture(pid, four, end, Arc::new(DwarfSymbolizer), Duration::ZERO);

    assert_eq!(none.confidence.overall, 1.0);
    assert!(none.confidence.overall > two.confidence.overall);
    assert!(two.confidence.overall > four.confidence.overall);
    assert_eq!(two.confidence.low_fields.len(), 2);
    assert_eq!(four.confidence.low_fields.len(), 4);
}

#[test]
fn b1_token_estimate_tracks_two_raw_payload_sizes() {
    let stat = captured_d_stat();
    let status = fixture_text("level0/status");
    let wchan = fixture_text("level0/wchan");
    let cmdline = fixture_bytes("level0/cmdline");
    let stack = fixture_text("level0/stack");
    let fds = vec!["0".to_owned(), "1".to_owned(), "2".to_owned()];

    let small_maps = fixture_text("level0/maps");
    let large_maps = fixture_text("maps/cat.txt");
    let small = introspect_with_inputs(
        FIXTURE_PID,
        &stat,
        &status,
        &small_maps,
        &wchan,
        &cmdline,
        &fds,
        &stack,
        &guest_agent::symbolize::FallbackSymbolizer,
    )
    .expect("small captured payload must assemble");
    let large = introspect_with_inputs(
        FIXTURE_PID,
        &stat,
        &status,
        &large_maps,
        &wchan,
        &cmdline,
        &fds,
        &stack,
        &guest_agent::symbolize::FallbackSymbolizer,
    )
    .expect("large captured payload must assemble");

    assert_ne!(small.cost_hint.token, large.cost_hint.token);
    for level0 in [small, large] {
        let json_bytes = serde_json::to_string(&level0).unwrap().len() as f32;
        let ratio = level0.cost_hint.token as f32 / json_bytes;
        assert!(
            (1.0 / 5.0..=1.0 / 3.0).contains(&ratio),
            "token ratio out of contract bounds: {ratio}"
        );
    }
}

#[test]
fn b3_fallback_keeps_kallsyms_and_only_reports_real_mismatch() {
    let stat = captured_d_stat();
    let status = fixture_text("level0/status");
    let maps = fixture_text("level0/maps");
    let cmdline = fixture_bytes("level0/cmdline");
    let stack = fixture_text("level0/stack");
    let matching_wchan = fixture_text("level0/wchan");
    let matching = introspect_with_inputs(
        FIXTURE_PID,
        &stat,
        &status,
        &maps,
        &matching_wchan,
        &cmdline,
        &[],
        &stack,
        &guest_agent::symbolize::FallbackSymbolizer,
    )
    .expect("fallback-symbolized captured stack must assemble");

    let Hotspot::Blocked { frames } = matching.hotspot else {
        panic!("D-state fixture must expose blocked frames");
    };
    assert!(!frames.is_empty());
    assert!(frames.iter().all(|frame| {
        frame
            .symbol
            .as_ref()
            .is_some_and(|symbol| symbol.source == SymbolConfidence::Kallsyms)
    }));
    assert!(matching.confidence.overall > 0.0);
    assert!(!has_path(&matching.confidence.low_fields, "state.wchan"));

    let mismatch = introspect_with_inputs(
        FIXTURE_PID,
        &stat,
        &status,
        &maps,
        "different_wait_function\n",
        &cmdline,
        &[],
        &stack,
        &guest_agent::symbolize::FallbackSymbolizer,
    )
    .expect("mismatched captured stack must still assemble");
    assert!(has_path(&mismatch.confidence.low_fields, "state.wchan"));
}

#[test]
fn b4_injected_clock_changes_span_in_the_public_service() {
    let (pid, snapshot, end) = complete_d_snapshot();
    let first = run_fixture(
        pid,
        snapshot.clone(),
        end,
        Arc::new(DwarfSymbolizer),
        Duration::from_millis(3),
    );
    let second = run_fixture(
        pid,
        snapshot,
        end,
        Arc::new(DwarfSymbolizer),
        Duration::from_millis(13),
    );

    assert_ne!(first.snapshot_span_ms, second.snapshot_span_ms);
    assert_eq!(first.snapshot_span_ms, 3);
    assert_eq!(second.snapshot_span_ms, 13);
}
