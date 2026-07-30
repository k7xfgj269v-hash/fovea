mod common;

use common::d7_fixtures::{fixture_bytes, fixture_text, stat_fixture};
use guest_agent::introspect_with_inputs;
use guest_agent::proc_view::{parse_stat, read_kernel_stack_from_str};
use guest_agent::schema::{Hotspot, LowConfidenceField, SymbolConfidence, Symbolized};
use guest_agent::symbolize::{SymbolizeError, Symbolizer};

const BACKEND_FAILURE: &str = "fixture backend unavailable";

struct DwarfSymbolizer;

impl Symbolizer for DwarfSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        Ok(Symbolized {
            name: format!("resolved_{addr:x}"),
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

fn captured_d_stat() -> String {
    String::from_utf8(stat_fixture('D')).expect("captured D-state stat must be UTF-8")
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

fn low_fields_at<'a>(fields: &'a [LowConfidenceField], path: &str) -> Vec<&'a LowConfidenceField> {
    fields.iter().filter(|field| field.path == path).collect()
}

#[test]
fn default_linux_entrypoint_uses_worker_client_before_fallback() {
    let source = include_str!("../src/introspect.rs");
    let entrypoint = source
        .split("pub fn introspect(pid: i32)")
        .nth(1)
        .expect("public introspect entrypoint must exist")
        .split("pub fn introspect_with")
        .next()
        .expect("introspect_with must follow the default entrypoint");
    let compact = entrypoint.split_whitespace().collect::<String>();

    let spawn = compact
        .find("matchspawn_kernel_symbolizer(SymbolizerWorkerConfig::default())")
        .expect("Linux default path must construct the kernel symbolizer worker");
    let client = compact
        .find("Arc::new(client)")
        .expect("successful worker initialization must inject its client");
    let shutdown = compact
        .find("handle.shutdown()")
        .expect("default path must explicitly shut down the worker");
    let fallback = compact
        .find("Arc::new(FallbackSymbolizer)")
        .expect("raw Kallsyms fallback must remain available on initialization failure");

    assert!(
        spawn < client && client < shutdown && shutdown < fallback,
        "the success path must use and close the worker before the fallback error arm"
    );
    assert_eq!(
        compact[..fallback]
            .matches("Arc::new(FallbackSymbolizer)")
            .count(),
        0,
        "FallbackSymbolizer must not be the constant default implementation"
    );
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
    let Hotspot::Blocked { frames } = level0.hotspot else {
        panic!("captured D-state fixture must produce blocked frames");
    };
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
fn live_kernel_worker_resolves_nonzero_text_symbol_concurrently() {
    use std::fs;
    use std::sync::Arc;
    use std::thread;

    use guest_agent::symbolize::{
        spawn_kernel_symbolizer, FallbackSymbolizer, SymbolizerWorkerConfig,
    };

    let kallsyms = fs::read_to_string("/proc/kallsyms")
        .expect("D5 live prerequisite failed: /proc/kallsyms must be readable");
    let candidates = kallsyms
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let addr = u64::from_str_radix(fields.next()?, 16).ok()?;
            let kind = fields.next()?.as_bytes().first().copied()?;
            let name = fields.next()?.to_owned();
            (addr != 0 && matches!(kind, b't' | b'T' | b'w' | b'W')).then_some((addr, name))
        })
        .take(4096)
        .collect::<Vec<_>>();
    assert!(
        !candidates.is_empty(),
        "D5 live prerequisite failed: /proc/kallsyms exposed no nonzero text symbols; check kptr_restrict and CI privileges"
    );

    let (client, handle) = spawn_kernel_symbolizer(SymbolizerWorkerConfig::default())
        .expect("D5 live prerequisite failed: kernel blazesym worker must start");
    let resolved = candidates
        .iter()
        .find_map(|(addr, raw_name)| {
            client
                .symbolize(*addr)
                .ok()
                .filter(|symbol| !symbol.name.is_empty())
                .map(|symbol| (*addr, raw_name.clone(), symbol))
        })
        .unwrap_or_else(|| {
            panic!(
                "D5 live acceptance failed: blazesym resolved none of {} nonzero kernel text symbols",
                candidates.len()
            )
        });

    let fallback = FallbackSymbolizer.symbolize(resolved.0);
    assert!(
        matches!(fallback, Err(SymbolizeError::NotFound { .. })),
        "the live worker result must be distinguishable from constant fallback behavior"
    );

    let client = Arc::new(client);
    let callers = (0..4)
        .map(|_| {
            let client = Arc::clone(&client);
            let addr = resolved.0;
            thread::spawn(move || client.symbolize(addr))
        })
        .collect::<Vec<_>>();
    for caller in callers {
        let symbol = caller
            .join()
            .expect("concurrent symbolizer caller must not panic")
            .expect("concurrent live symbolization must succeed");
        assert!(!symbol.name.is_empty());
        assert_ne!(symbol.source, SymbolConfidence::None);
    }

    handle
        .shutdown()
        .expect("kernel symbolizer worker must shut down cleanly");
    assert_eq!(
        client.symbolize(resolved.0).unwrap_err(),
        SymbolizeError::WorkerStopped
    );
}
