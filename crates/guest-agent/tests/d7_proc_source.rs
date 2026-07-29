mod common;

use guest_agent::{ProcDegradation, ProcSnapshot};

use common::d7_fixtures::fixture_text;

fn assert_u32(_: u32) {}

#[test]
fn proc_snapshot_uses_u32_fd_count_without_names_and_transports_raw_source_evidence() {
    let degradations = [
        ("identity.comm", "stat"),
        ("identity.uid", "status"),
        ("resource.ctxt_switches", "status"),
        ("mem_shape", "maps"),
        ("state.wchan", "wchan"),
        ("hotspot.frames", "stack"),
        ("identity.cgroup", "cgroup"),
        ("identity.exe", "exe"),
        ("identity.cmdline", "cmdline"),
    ]
    .into_iter()
    .map(|(path, source)| {
        ProcDegradation::new(
            path,
            format!("{source} contains invalid UTF-8 and used U+FFFD replacement"),
        )
    })
    .collect::<Vec<_>>();
    let snapshot = ProcSnapshot {
        stat: fixture_text("stat/stat-running.txt"),
        status: fixture_text("status/cat.txt"),
        maps: fixture_text("maps/cat.txt"),
        wchan: None,
        cmdline: b"cat\0".to_vec(),
        nr_fds: 3,
        kernel_stack: None,
        exe: Some("/usr/bin/cat".into()),
        cgroup: None,
        degradations: degradations.clone(),
        system_cpu_ticks: 1,
        logical_cpus: 1,
        page_size_bytes: 4096,
    };

    assert_u32(snapshot.nr_fds);
    assert_eq!(snapshot.nr_fds, 3);
    assert_eq!(snapshot.degradations, degradations);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ascii_control_snapshot_has_no_lossy_utf8_evidence() {
    use guest_agent::{LinuxProcSource, ProcSource};

    let pid = std::process::id() as i32;
    let snapshot = LinuxProcSource::new()
        .snapshot(pid)
        .expect("ASCII test process must be readable from procfs");

    assert_u32(snapshot.nr_fds);
    assert!(snapshot.nr_fds > 0);
    assert!(
        snapshot.degradations.is_empty(),
        "valid UTF-8 control must not be marked degraded: {:?}",
        snapshot.degradations
    );
}
