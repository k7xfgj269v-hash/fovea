mod common;

use common::d7_fixtures::{fixture_bytes, fixture_text, manifest, stat_fixture, STATE_FIXTURES};
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

    for unknown_state in ['?', 'q', '~'] {
        let mut unknown = stat_fixture('S');
        let state_offset = stat_state_offset(&unknown);
        unknown[state_offset] = unknown_state as u8;
        let parsed = parse_stat(std::str::from_utf8(&unknown).unwrap())
            .expect("unknown nonempty state must not fail the whole snapshot");
        assert_eq!(parsed.state, RunState::Unknown(unknown_state));
    }

    let mut unknown = stat_fixture('S');
    let state_offset = stat_state_offset(&unknown);
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
    let captured = fixture_bytes("maps/cat.txt");
    let mut captured_lines = captured_map_lines("maps/cat.txt");
    assert_eq!(captured_lines.len(), 48);

    let clean = parse_maps_with_diagnostics(std::str::from_utf8(&captured).unwrap()).unwrap();

    assert_eq!(clean.valid_line_count, 48);
    assert_eq!(clean.skipped_line_count, 0);
    assert!(clean.degradations.is_empty());
    assert_eq!(histogram_count(&clean), 48);

    let perms_offset = map_perms_offset(&captured_lines[0]);
    captured_lines[0][perms_offset] = b'q';
    truncate_map_line_after_address(&mut captured_lines[17]);
    let mixed_bytes = captured_lines.concat();
    let mixed = parse_maps_with_diagnostics(std::str::from_utf8(&mixed_bytes).unwrap()).unwrap();

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
    let mut malformed = captured_map_lines("maps/cat.txt");
    assert_eq!(malformed.len(), 48);
    for line in &mut malformed {
        truncate_map_line_after_address(line);
    }
    let malformed_bytes = malformed.concat();

    let parsed =
        parse_maps_with_diagnostics(std::str::from_utf8(&malformed_bytes).unwrap()).unwrap();

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
fn maps_require_exact_permissions_pattern() {
    let captured = captured_boundary_line(b"/short-file");
    let perms_offset = map_perms_offset(&captured);
    assert_eq!(&captured[perms_offset..perms_offset + 4], b"r--s");

    let clean = parse_maps_with_diagnostics(std::str::from_utf8(&captured).unwrap()).unwrap();
    assert_eq!(clean.valid_line_count, 1);
    assert_eq!(clean.skipped_line_count, 0);

    for (index, invalid_byte) in [(0, b'x'), (1, b'x'), (2, b'w'), (3, b'x')] {
        let mut mutated = captured.clone();
        mutated[perms_offset + index] = invalid_byte;
        let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&mutated).unwrap()).unwrap();
        assert_eq!(parsed.valid_line_count, 0, "perms byte {index}");
        assert_eq!(parsed.skipped_line_count, 1, "perms byte {index}");
        assert_eq!(
            parsed.degradations[0].reason,
            "skipped 1 malformed maps lines"
        );
    }

    for mutated_len in [3usize, 5usize] {
        let mut mutated = captured.clone();
        if mutated_len == 3 {
            mutated.remove(perms_offset + 3);
        } else {
            mutated.insert(perms_offset + 4, b'p');
        }
        let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&mutated).unwrap()).unwrap();
        assert_eq!(
            parsed.valid_line_count, 0,
            "permissions length {mutated_len}"
        );
        assert_eq!(
            parsed.skipped_line_count, 1,
            "permissions length {mutated_len}"
        );
    }

    for valid_permissions in [b"---p", b"---s", b"rwxp", b"rwxs"] {
        let mut mutated = captured.clone();
        mutated[perms_offset..perms_offset + 4].copy_from_slice(valid_permissions);
        let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&mutated).unwrap()).unwrap();
        assert_eq!(
            parsed.valid_line_count, 1,
            "permissions {valid_permissions:?}"
        );
        assert_eq!(
            parsed.skipped_line_count, 0,
            "permissions {valid_permissions:?}"
        );
    }
}

#[test]
fn captured_top_map_backing_boundaries_preserve_path_bytes() {
    for (marker, expected_len) in [
        (b"/short-file".as_slice(), 35usize),
        (b"ascii255-".as_slice(), 255usize),
        (b"ascii256-".as_slice(), 256usize),
        (b"/trailing-space ".as_slice(), 40usize),
        (b"/trailing-tab\t".as_slice(), 38usize),
    ] {
        let line = captured_boundary_line(marker);
        let expected = captured_path(&line);
        assert_eq!(expected.len(), expected_len);

        let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&line).unwrap()).unwrap();
        assert_eq!(only_backing(&parsed), expected);
        assert!(parsed.degradations.is_empty());
    }

    let ascii257 = captured_boundary_line(b"ascii257-");
    let expected = captured_path(&ascii257);
    assert_eq!(expected.len(), TOP_MAP_BACKING_MAX_BYTES + 1);
    let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&ascii257).unwrap()).unwrap();
    assert_eq!(
        only_backing(&parsed),
        &expected[..TOP_MAP_BACKING_MAX_BYTES]
    );
    assert_eq!(parsed.degradations.len(), 1);
    assert_eq!(parsed.degradations[0].path, "mem_shape.top_n[0].backing");
    assert_eq!(
        parsed.degradations[0].reason,
        "backing truncated from 257 to 256 UTF-8 bytes"
    );

    let multibyte = captured_boundary_line(b"/multibyte-");
    let expected = captured_path(&multibyte);
    assert_eq!(expected.len(), TOP_MAP_BACKING_MAX_BYTES + 1);
    assert!(expected.is_char_boundary(254));
    assert!(!expected.is_char_boundary(TOP_MAP_BACKING_MAX_BYTES));

    let parsed = parse_maps_with_diagnostics(std::str::from_utf8(&multibyte).unwrap()).unwrap();
    assert_eq!(only_backing(&parsed), &expected[..254]);
    assert_eq!(parsed.degradations.len(), 1);
    assert_eq!(parsed.degradations[0].path, "mem_shape.top_n[0].backing");
    assert_eq!(
        parsed.degradations[0].reason,
        "backing truncated from 257 to 254 UTF-8 bytes"
    );

    let trailing_space = captured_boundary_line(b"/trailing-space ");
    assert!(only_backing(
        &parse_maps_with_diagnostics(std::str::from_utf8(&trailing_space).unwrap()).unwrap()
    )
    .ends_with(' '));

    let trailing_tab = captured_boundary_line(b"/trailing-tab\t");
    assert!(only_backing(
        &parse_maps_with_diagnostics(std::str::from_utf8(&trailing_tab).unwrap()).unwrap()
    )
    .ends_with('\t'));
}

#[test]
fn cgroup_prefers_unified_and_keeps_v1_fallback() {
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/beijing-v2.txt")).unwrap(),
        Some("/user.slice/user-1000.slice/session-45186.scope".into())
    );
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/lxc-hybrid-2845.txt")).unwrap(),
        Some("/user.slice/user-1000.slice/session-2.scope".into())
    );
    assert_eq!(
        parse_cgroup(&fixture_text("cgroup/lxc-v1-only-1909.txt")).unwrap(),
        Some("/lxc/ca0cc7d3-33b2-4b5d-a78a-d0a46fcfd2f5".into())
    );

    let invalid_unified = make_unified_path_relative(&fixture_text("cgroup/lxc-hybrid-2845.txt"));
    assert_eq!(parse_cgroup(&invalid_unified).unwrap(), Some("/".into()));

    let no_valid_path = make_unified_path_relative(&fixture_text("cgroup/beijing-v2.txt"));
    assert!(matches!(
        parse_cgroup(&no_valid_path),
        Err(ProcError::Parse { what, reason })
            if what == "cgroup" && reason.contains("path 不是绝对路径")
    ));
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
    assert_eq!(beijing.captured_at, "2026-07-29T15:49:42Z");
    assert_eq!(beijing.kernel_release, "5.15.0-171-generic");
    assert_eq!(beijing.architecture, "x86_64");
    assert_eq!(beijing.command, "cat /proc/self/cgroup");
    assert_eq!(beijing.provenance.kind, "captured");
    assert_eq!(beijing.provenance.source, None);

    let maps = manifest
        .fixtures
        .iter()
        .find(|record| record.path == "maps/boundaries-beijing.txt")
        .unwrap();
    assert_eq!(maps.kind, "proc_maps");
    assert_eq!(maps.captured_at, "2026-07-29T17:17:13Z");
    assert_eq!(maps.kernel_release, "5.15.0-171-generic");
    assert_eq!(maps.architecture, "x86_64");
    assert_eq!(
        maps.command,
        "python3 mmap boundary capture; read /proc/self/maps"
    );
    assert_eq!(
        maps.sha256,
        "d93a35d5a7f2f1e479641f1ca1f7da285ae0311458a0115d4a93b10dfb13be3a"
    );
    assert_eq!(maps.provenance.kind, "captured");
    assert_eq!(maps.provenance.source, None);

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

fn captured_map_lines(relative: &str) -> Vec<Vec<u8>> {
    fixture_bytes(relative)
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn captured_boundary_line(marker: &[u8]) -> Vec<u8> {
    captured_map_lines("maps/boundaries-beijing.txt")
        .into_iter()
        .find(|line| find_bytes(line, marker).is_some())
        .unwrap_or_else(|| panic!("captured boundary map missing marker {marker:?}"))
}

fn captured_path(line: &[u8]) -> &str {
    let start = find_bytes(line, b"/tmp/").expect("captured map must contain an absolute path");
    let end = line
        .strip_suffix(b"\n")
        .expect("captured map line must retain its newline")
        .len();
    std::str::from_utf8(&line[start..end]).expect("captured map path must be UTF-8")
}

fn map_perms_offset(line: &[u8]) -> usize {
    let address_end = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .expect("captured map must contain permissions");
    line[address_end..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|offset| address_end + offset)
        .expect("captured map must contain permissions")
}

fn truncate_map_line_after_address(line: &mut Vec<u8>) {
    let address_end = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .expect("captured map must contain an address boundary");
    line.truncate(address_end);
    line.push(b'\n');
}

fn make_unified_path_relative(cgroup: &str) -> String {
    let mut bytes = cgroup.as_bytes().to_vec();
    let unified = find_bytes(&bytes, b"0::/").expect("captured cgroup must contain a v2 entry");
    bytes.remove(unified + 3);
    String::from_utf8(bytes).expect("cgroup mutation must remain UTF-8")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn only_backing(parsed: &guest_agent::proc_view::ParsedMaps) -> &str {
    parsed.mem_shape.top_n[0]
        .backing
        .as_deref()
        .expect("derived map must retain a backing")
}
