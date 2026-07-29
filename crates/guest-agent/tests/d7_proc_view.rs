mod common;

use common::d7_fixtures::{fixture_text, manifest, stat_fixture, STATE_FIXTURES};
use guest_agent::proc_view::{
    parse_cgroup, parse_maps_with_diagnostics, parse_stat, parse_status, TOP_MAP_BACKING_MAX_BYTES,
};
use guest_agent::ProcError;
use introspect_schema::RunState;

#[test]
fn all_captured_run_states_parse_and_unknown_falls_back() {
    assert_eq!(
        STATE_FIXTURES.map(|(state, _)| state),
        ['R', 'S', 'D', 'Z', 'T', 't', 'X', 'P', 'I']
    );

    for (state, _) in STATE_FIXTURES {
        let fixture = String::from_utf8(stat_fixture(state)).expect("stat fixture must be UTF-8");
        let parsed = parse_stat(&fixture).expect("captured state must parse");
        assert_eq!(parsed.state, RunState::from_char(state));
    }

    let mut unknown = stat_fixture('S');
    let state_offset = stat_state_offset(&unknown);
    unknown[state_offset] = b'?';
    let parsed = parse_stat(std::str::from_utf8(&unknown).unwrap())
        .expect("unknown nonempty state must not fail the whole snapshot");
    assert_eq!(parsed.state, RunState::Unknown('?'));

    unknown.remove(state_offset);
    match parse_stat(std::str::from_utf8(&unknown).unwrap()) {
        Err(ProcError::Parse { what, reason }) => {
            assert_eq!(what, "stat.state");
            assert_eq!(reason, "空状态");
        }
        result => panic!("empty state must be rejected as stat.state parse error: {result:?}"),
    }
}

#[test]
fn status_tracks_each_context_switch_line_presence() {
    let captured = fixture_text("status/cat.txt");
    let complete = parse_status(&captured).unwrap();
    assert!(complete.has_voluntary_ctxt_switches);
    assert!(complete.has_nonvoluntary_ctxt_switches);

    let without_voluntary = remove_status_line(&captured, "voluntary_ctxt_switches:");
    let parsed = parse_status(&without_voluntary).unwrap();
    assert!(!parsed.has_voluntary_ctxt_switches);
    assert!(parsed.has_nonvoluntary_ctxt_switches);

    let without_nonvoluntary = remove_status_line(&captured, "nonvoluntary_ctxt_switches:");
    let parsed = parse_status(&without_nonvoluntary).unwrap();
    assert!(parsed.has_voluntary_ctxt_switches);
    assert!(!parsed.has_nonvoluntary_ctxt_switches);

    let without_either = remove_status_line(
        &remove_status_line(&captured, "voluntary_ctxt_switches:"),
        "nonvoluntary_ctxt_switches:",
    );
    let parsed = parse_status(&without_either).unwrap();
    assert!(!parsed.has_voluntary_ctxt_switches);
    assert!(!parsed.has_nonvoluntary_ctxt_switches);
}

#[test]
fn maps_skip_only_malformed_lines_and_report_the_exact_count() {
    let captured = fixture_text("maps/cat.txt");
    let captured_lines: Vec<_> = captured.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(captured_lines.len(), 48);

    let clean = parse_maps_with_diagnostics(&captured).unwrap();

    assert_eq!(clean.valid_line_count, 48);
    assert_eq!(clean.skipped_line_count, 0);
    assert!(clean.degradations.is_empty());
    assert_eq!(histogram_count(&clean), 48);

    let mut mixed_lines = captured_lines.clone();
    mixed_lines[0] = "malformed maps line";
    mixed_lines[17] = "also malformed";
    let mixed = parse_maps_with_diagnostics(&mixed_lines.join("\n")).unwrap();

    assert_eq!(mixed.valid_line_count, 46);
    assert_eq!(mixed.skipped_line_count, 2);
    assert_eq!(histogram_count(&mixed), 46);
    assert_eq!(mixed.degradations.len(), 1);
    assert_eq!(mixed.degradations[0].path, "mem_shape");
    assert_eq!(
        mixed.degradations[0].reason,
        "skipped 2 malformed maps lines"
    );
}

#[test]
fn entirely_malformed_maps_are_an_explicit_empty_projection() {
    let captured = fixture_text("maps/cat.txt");
    let malformed: Vec<_> = captured
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(malformed.len(), 48);

    let parsed = parse_maps_with_diagnostics(&malformed.join("\n")).unwrap();

    assert_eq!(parsed.valid_line_count, 0);
    assert_eq!(parsed.skipped_line_count, 48);
    assert!(parsed.mem_shape.histogram.is_empty());
    assert!(parsed.mem_shape.top_n.is_empty());
    assert_eq!(histogram_count(&parsed), 0);
    assert_eq!(parsed.degradations.len(), 1);
    assert_eq!(parsed.degradations[0].path, "mem_shape");
    assert_eq!(
        parsed.degradations[0].reason,
        "skipped 48 malformed maps lines"
    );
}

#[test]
fn top_map_backing_is_bounded_at_utf8_boundaries() {
    let short = "/tmp/d7";
    let parsed = parse_maps_with_diagnostics(&map_with_backing(short)).unwrap();
    assert_eq!(only_backing(&parsed), short);
    assert!(parsed.degradations.is_empty());

    let exact = format!("/{}", "a".repeat(TOP_MAP_BACKING_MAX_BYTES - 1));
    let parsed = parse_maps_with_diagnostics(&map_with_backing(&exact)).unwrap();
    assert_eq!(only_backing(&parsed), exact);
    assert!(parsed.degradations.is_empty());

    let oversized_ascii = format!("/{}", "a".repeat(TOP_MAP_BACKING_MAX_BYTES));
    let parsed = parse_maps_with_diagnostics(&map_with_backing(&oversized_ascii)).unwrap();
    assert_eq!(
        only_backing(&parsed),
        &oversized_ascii[..TOP_MAP_BACKING_MAX_BYTES]
    );
    assert_eq!(only_backing(&parsed).len(), TOP_MAP_BACKING_MAX_BYTES);
    assert_eq!(parsed.degradations.len(), 1);
    assert_eq!(parsed.degradations[0].path, "mem_shape.top_n[0].backing");
    assert_eq!(
        parsed.degradations[0].reason,
        "backing truncated from 257 to 256 UTF-8 bytes"
    );

    let oversized_multibyte = format!("/{}", "é".repeat(TOP_MAP_BACKING_MAX_BYTES / 2));
    let parsed = parse_maps_with_diagnostics(&map_with_backing(&oversized_multibyte)).unwrap();
    let backing = only_backing(&parsed);
    assert!(backing.len() <= TOP_MAP_BACKING_MAX_BYTES);
    assert_eq!(backing.len(), TOP_MAP_BACKING_MAX_BYTES - 1);
    assert_eq!(backing, format!("/{}", "é".repeat(127)));
    assert_eq!(parsed.degradations.len(), 1);
    assert_eq!(parsed.degradations[0].path, "mem_shape.top_n[0].backing");
    assert_eq!(
        parsed.degradations[0].reason,
        "backing truncated from 257 to 255 UTF-8 bytes"
    );
}

#[test]
fn cgroup_prefers_unified_and_keeps_v1_fallback() {
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/beijing-v2.txt")).unwrap(),
        Some("/user.slice/user-1000.slice/session-45050.scope".into())
    );
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/lxc-hybrid-2845.txt")).unwrap(),
        Some("/user.slice/user-1000.slice/session-2.scope".into())
    );
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/lxc-v1-only-1909.txt")).unwrap(),
        Some("/lxc/ca0cc7d3-33b2-4b5d-a78a-d0a46fcfd2f5".into())
    );
}

#[test]
fn cgroup_fixture_manifest_records_capture_provenance() {
    let manifest = manifest();

    let beijing = manifest
        .fixtures
        .iter()
        .find(|record| record.path == "cgroup/beijing-v2.txt")
        .unwrap();
    assert_eq!(beijing.kind, "proc_cgroup");
    assert_eq!(beijing.captured_at, "2026-07-29");
    assert_eq!(beijing.kernel_release, "5.15.0-171-generic");
    assert_eq!(beijing.architecture, "x86_64");
    assert_eq!(beijing.command, "cat /proc/self/cgroup");
    assert_eq!(beijing.provenance.kind, "captured");
    assert_eq!(beijing.provenance.source, None);

    for (path, source_date, kernel_release, source_url) in [
        (
            "cgroup/lxc-v1-only-1909.txt",
            "2017-11-08T10:09:16Z",
            "4.9.0-4-amd64",
            "https://github.com/lxc/lxc/issues/1909",
        ),
        (
            "cgroup/lxc-hybrid-2845.txt",
            "2019-02-11T22:19:03Z",
            "4.18.0-15-generic",
            "https://github.com/lxc/lxc/issues/2845",
        ),
    ] {
        let record = manifest
            .fixtures
            .iter()
            .find(|record| record.path == path)
            .unwrap();
        assert_eq!(record.kind, "proc_cgroup");
        assert_eq!(record.captured_at, source_date);
        assert_eq!(record.kernel_release, kernel_release);
        assert_eq!(record.architecture, "x86_64");
        assert_eq!(record.command, "cat /proc/self/cgroup");
        assert_eq!(record.provenance.kind, "external_capture");
        assert_eq!(record.provenance.source.as_deref(), Some(source_url));
        assert_eq!(record.provenance.mutation, None);
    }
}

fn stat_state_offset(stat: &[u8]) -> usize {
    stat.iter()
        .rposition(|byte| *byte == b')')
        .expect("captured stat must contain a closing parenthesis")
        + 2
}

fn remove_status_line(captured: &str, prefix: &str) -> String {
    let mut derived = captured
        .lines()
        .filter(|line| !line.starts_with(prefix))
        .collect::<Vec<_>>()
        .join("\n");
    derived.push('\n');
    derived
}

fn histogram_count(parsed: &guest_agent::proc_view::ParsedMaps) -> usize {
    parsed
        .mem_shape
        .histogram
        .iter()
        .map(|bucket| bucket.count as usize)
        .sum()
}

fn map_with_backing(backing: &str) -> String {
    let captured = fixture_text("maps/cat.txt");
    let line = captured
        .lines()
        .find(|line| line.split_whitespace().count() >= 6)
        .expect("captured maps fixture must contain a file-backed mapping");
    let original_backing = line.split_whitespace().nth(5).unwrap();
    let path_start = line
        .find(original_backing)
        .expect("captured map backing must be locatable");
    format!("{}{backing}\n", &line[..path_start])
}

fn only_backing(parsed: &guest_agent::proc_view::ParsedMaps) -> &str {
    parsed.mem_shape.top_n[0]
        .backing
        .as_deref()
        .expect("derived map must retain a backing")
}
