#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use guest_agent::{introspect, ProcError};

const PYTHON_FIXTURE: &str = r#"
import ctypes
import mmap
import os
import sys
import tempfile

invalid = sys.argv[1] == "invalid"
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int

name = ctypes.create_string_buffer(
    b"fovea-\xff" if invalid else b"fovea-ascii"
)
if libc.prctl(15, ctypes.cast(name, ctypes.c_void_p), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")

tmp = tempfile.TemporaryDirectory()
path = os.fsencode(tmp.name) + b"/mapped-" + (b"\xff" if invalid else b"ascii")
size = 32 * 1024 * 1024
fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
os.ftruncate(fd, size)
mapping = mmap.mmap(fd, size, access=mmap.ACCESS_WRITE)
print(os.getpid(), flush=True)
sys.stdin.buffer.read(1)
mapping.close()
os.close(fd)
tmp.cleanup()
"#;

struct FixtureChild {
    child: Child,
    pid: i32,
}

impl FixtureChild {
    fn spawn(invalid: bool) -> Self {
        let mode = if invalid { "invalid" } else { "ascii" };
        let mut child = Command::new("python3")
            .args(["-c", PYTHON_FIXTURE, mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Linux CI must provide python3 for the D7 live fixture");

        let stdout = child
            .stdout
            .take()
            .expect("fixture child stdout must be piped");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("fixture child must report its pid");
        let pid = line
            .trim()
            .parse()
            .expect("fixture child pid must be numeric");

        Self { child, pid }
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = stdin.write_all(b"x");
        }
        let _ = self.child.wait();
    }
}

fn has_low_field(level0: &guest_agent::schema::Level0, path: &str) -> bool {
    level0
        .confidence
        .low_fields
        .iter()
        .any(|field| field.path == path)
}

#[test]
#[ignore]
fn non_utf8_proc_inputs_are_lossy_but_observable() {
    let fixture = FixtureChild::spawn(true);
    let level0 = introspect(fixture.pid).expect("non-UTF-8 proc inputs must remain introspectable");

    assert!(
        level0.identity.comm.contains('\u{FFFD}'),
        "comm must expose the replacement character: {:?}",
        level0.identity.comm
    );
    assert!(has_low_field(&level0, "identity.comm"));
    assert!(has_low_field(&level0, "mem_shape"));
    assert!(
        level0
            .mem_shape
            .top_n
            .iter()
            .filter_map(|mapping| mapping.backing.as_deref())
            .any(|backing| backing.contains('\u{FFFD}')),
        "the large invalid-path mmap must remain visible in top_n: {:?}",
        level0.mem_shape.top_n
    );
}

#[test]
#[ignore]
fn ascii_control_proc_inputs_have_no_utf8_degradation() {
    let fixture = FixtureChild::spawn(false);
    let level0 = introspect(fixture.pid).expect("ASCII proc inputs must introspect");

    assert!(
        !level0
            .confidence
            .low_fields
            .iter()
            .any(|field| field.reason.contains("U+FFFD")),
        "ASCII control process unexpectedly reported lossy decoding: {:?}",
        level0.confidence.low_fields
    );
}

#[test]
#[ignore]
fn full_numeric_proc_scan_has_no_parse_failures() {
    let pids = fs::read_dir("/proc")
        .expect("Linux CI must expose procfs")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.parse::<i32>().ok())
        .collect::<Vec<_>>();

    let mut parse_failures = Vec::new();
    let mut unexpected = Vec::new();
    for pid in pids {
        match introspect(pid) {
            Ok(_) => {}
            Err(ProcError::ProcNotFound { .. } | ProcError::Permission) => {}
            Err(error) => {
                let (kind, reason, _) = error.to_error_report();
                if kind == "proc_parse_failed" {
                    if parse_failures.len() < 32 {
                        parse_failures.push(format!("pid={pid}: {reason}"));
                    }
                } else if unexpected.len() < 32 {
                    unexpected.push(format!("pid={pid}: {kind}: {reason}"));
                }
            }
        }
    }

    assert!(
        parse_failures.is_empty(),
        "numeric /proc scan produced parse failures: {parse_failures:?}"
    );
    assert!(
        unexpected.is_empty(),
        "numeric /proc scan produced unexpected failures: {unexpected:?}"
    );
}
