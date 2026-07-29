//! `/proc` access ports and the Linux procfs adapter.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::degradation::ProcDegradation;

/// All procfs inputs needed to assemble one Level 0 result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnapshot {
    pub stat: String,
    pub status: String,
    pub maps: String,
    pub wchan: Option<String>,
    pub cmdline: Vec<u8>,
    pub nr_fds: u32,
    pub kernel_stack: Option<String>,
    pub exe: Option<String>,
    pub cgroup: Option<String>,
    pub degradations: Vec<ProcDegradation>,
    pub system_cpu_ticks: u64,
    pub logical_cpus: u32,
    pub page_size_bytes: u64,
}

/// Counter state used by the short CPU sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCounters {
    pub process_ticks: u64,
    pub system_ticks: u64,
    pub process_start_time_ticks: u64,
}

/// Structured procfs failure modes.
#[derive(Debug, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcError {
    #[error("pid {pid} 无效")]
    InvalidPid { pid: i32 },
    #[error("pid {pid} 不存在")]
    ProcNotFound { pid: i32 },
    #[error("读 /proc 权限不足")]
    Permission,
    #[error("读取 {what} 失败：{reason}")]
    Read { what: String, reason: String },
    #[error("解析 {what} 失败：{reason}")]
    Parse { what: String, reason: String },
    #[error("当前平台不支持 proc introspection")]
    UnsupportedPlatform,
    #[error("运行时页大小无效")]
    InvalidPageSize,
    #[error("CPU 短采样读取失败")]
    CpuSampleFailed,
    #[error("尚未实现（M1 第二刀）")]
    NotImplemented,
}

impl ProcError {
    pub fn to_error_report(&self) -> (&'static str, String, Option<&'static str>) {
        match self {
            ProcError::InvalidPid { pid } => (
                "proc_invalid_pid",
                format!("pid {pid} 无效"),
                Some("传入大于等于 1 的进程 ID"),
            ),
            ProcError::ProcNotFound { pid } => (
                "proc_not_found",
                format!("pid {pid} 不存在或已退出"),
                Some("重试前用 introspect(pid=1) 或类似探活；确认 pid 仍存活"),
            ),
            ProcError::Permission => (
                "proc_permission_denied",
                "读 /proc/<pid>/ 权限不足".into(),
                Some("guest-agent 需挂足够权限（root 或 CAP_SYS_PTRACE 等）"),
            ),
            ProcError::Read { .. } => (
                "proc_read_failed",
                "读取必要的 procfs 数据失败".into(),
                Some("确认 procfs 已挂载、目标进程仍存活且读取权限充足"),
            ),
            ProcError::Parse { what, .. } => {
                let reason = match public_proc_field(what) {
                    Some(field) => format!("procfs 数据字段 {field} 格式无效"),
                    None => "procfs 数据格式无效".into(),
                };
                (
                    "proc_parse_failed",
                    reason,
                    Some("确认目标内核 procfs 格式与 guest-agent 兼容"),
                )
            }
            ProcError::UnsupportedPlatform => (
                "proc_unsupported_platform",
                "proc introspection 仅支持 Linux".into(),
                Some("在 Linux guest 中运行 guest-agent"),
            ),
            ProcError::InvalidPageSize => (
                "proc_invalid_page_size",
                "运行时页大小无效，无法计算 RSS 字节数".into(),
                Some("检查 libc sysconf(_SC_PAGESIZE) 与 guest 运行环境"),
            ),
            ProcError::CpuSampleFailed => (
                "proc_cpu_sample_failed",
                "CPU 短采样计数器读取失败".into(),
                Some("确认目标进程仍可读取后重试 introspect"),
            ),
            ProcError::NotImplemented => (
                "not_implemented",
                "introspect 该路径尚未在当前 milestone 实现".into(),
                None,
            ),
        }
    }
}

fn public_proc_field(what: &str) -> Option<&str> {
    const EXACT_FIELDS: [&str; 7] = [
        "stat",
        "status",
        "maps",
        "cgroup",
        "proc_stat.cpu",
        "proc_stat.logical_cpus",
        "fd entry",
    ];
    let is_named_field = ["stat.", "status."].iter().any(|prefix| {
        what.strip_prefix(prefix).is_some_and(|field| {
            !field.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    });
    if EXACT_FIELDS.contains(&what) || is_named_field {
        Some(what)
    } else {
        None
    }
}

/// Port for process snapshots and short CPU counter samples.
pub trait ProcSource: Send + Sync {
    fn snapshot(&self, pid: i32) -> Result<ProcSnapshot, ProcError>;
    fn cpu_counters(&self, pid: i32) -> Result<CpuCounters, ProcError>;
}

/// Injectable wait used between CPU counter reads.
pub trait SampleClock: Send + Sync {
    fn sleep(&self, duration: Duration);
}

#[cfg(target_os = "linux")]
const ESRCH_RAW_OS_ERROR: i32 = libc::ESRCH;
#[cfg(all(test, not(target_os = "linux")))]
const ESRCH_RAW_OS_ERROR: i32 = 3;

#[cfg(any(test, target_os = "linux"))]
fn read_adjacent_cpu_pair<Process, System, ReadProcess, ReadSystem>(
    mut read_process: ReadProcess,
    mut read_system: ReadSystem,
) -> Result<(Process, System), ProcError>
where
    ReadProcess: FnMut() -> Result<Process, ProcError>,
    ReadSystem: FnMut() -> Result<System, ProcError>,
{
    let process = read_process()?;
    let system = read_system()?;
    Ok((process, system))
}

#[cfg(any(test, target_os = "linux"))]
const STAT_LOSSY_PATHS: &[&str] = &["identity.comm"];
#[cfg(any(test, target_os = "linux"))]
const STATUS_LOSSY_PATHS: &[&str] = &["identity.uid", "resource.ctxt_switches"];
#[cfg(any(test, target_os = "linux"))]
const MAPS_LOSSY_PATHS: &[&str] = &["mem_shape"];
#[cfg(any(test, target_os = "linux"))]
const WCHAN_LOSSY_PATHS: &[&str] = &["state.wchan"];
#[cfg(any(test, target_os = "linux"))]
const STACK_LOSSY_PATHS: &[&str] = &["hotspot.frames"];
#[cfg(any(test, target_os = "linux"))]
const CGROUP_LOSSY_PATHS: &[&str] = &["identity.cgroup"];
#[cfg(any(test, target_os = "linux"))]
const EXE_LOSSY_PATHS: &[&str] = &["identity.exe"];
#[cfg(any(test, target_os = "linux"))]
const CMDLINE_LOSSY_PATHS: &[&str] = &["identity.cmdline"];

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedProcText {
    value: String,
    degradations: Vec<ProcDegradation>,
}

#[cfg(any(test, target_os = "linux"))]
fn invalid_utf8_degradations(
    bytes: &[u8],
    what: &str,
    affected_paths: &[&str],
) -> Vec<ProcDegradation> {
    if std::str::from_utf8(bytes).is_ok() {
        return Vec::new();
    }

    let reason = format!("{what} 包含非 UTF-8 字节，已用 U+FFFD 替换");
    affected_paths
        .iter()
        .map(|path| ProcDegradation::new(*path, reason.clone()))
        .collect()
}

#[cfg(any(test, target_os = "linux"))]
fn decode_proc_text(bytes: &[u8], what: &str, affected_paths: &[&str]) -> DecodedProcText {
    DecodedProcText {
        value: String::from_utf8_lossy(bytes).into_owned(),
        degradations: invalid_utf8_degradations(bytes, what, affected_paths),
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessGeneration {
    pid: i32,
    start_time_ticks: u64,
}

#[cfg(any(test, target_os = "linux"))]
impl From<&crate::proc_view::Stat> for ProcessGeneration {
    fn from(stat: &crate::proc_view::Stat) -> Self {
        Self {
            pid: stat.pid,
            start_time_ticks: stat.process_start_time_ticks,
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn with_stable_process_generation<T, ReadSnapshot, ReadFinalGeneration>(
    requested_pid: i32,
    initial: ProcessGeneration,
    read_snapshot: ReadSnapshot,
    read_final_generation: ReadFinalGeneration,
) -> Result<T, ProcError>
where
    ReadSnapshot: FnOnce() -> Result<T, ProcError>,
    ReadFinalGeneration: FnOnce() -> Result<ProcessGeneration, ProcError>,
{
    if initial.pid != requested_pid {
        return Err(ProcError::ProcNotFound { pid: requested_pid });
    }

    let snapshot = read_snapshot()?;
    let final_generation = read_final_generation()?;
    if final_generation.pid != requested_pid || final_generation != initial {
        return Err(ProcError::ProcNotFound { pid: requested_pid });
    }

    Ok(snapshot)
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcIoScope {
    Process,
    Global,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcIoErrorClass {
    ProcNotFound,
    Permission,
    InvalidData,
    Other,
}

#[cfg(any(test, target_os = "linux"))]
fn classify_proc_io(error: &std::io::Error, scope: ProcIoScope) -> ProcIoErrorClass {
    if scope == ProcIoScope::Process
        && (error.kind() == std::io::ErrorKind::NotFound
            || error.raw_os_error() == Some(ESRCH_RAW_OS_ERROR))
    {
        return ProcIoErrorClass::ProcNotFound;
    }

    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ProcIoErrorClass::Permission,
        std::io::ErrorKind::InvalidData => ProcIoErrorClass::InvalidData,
        _ => ProcIoErrorClass::Other,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSampleClock;

impl SampleClock for ThreadSampleClock {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{Error, ErrorKind};
    use std::os::unix::ffi::OsStringExt;
    use std::path::{Path, PathBuf};

    use introspect_schema::RunState;

    use super::{
        classify_proc_io, decode_proc_text, invalid_utf8_degradations, read_adjacent_cpu_pair,
        with_stable_process_generation, CpuCounters, DecodedProcText, ProcError, ProcIoErrorClass,
        ProcIoScope, ProcSnapshot, ProcSource, ProcessGeneration, CGROUP_LOSSY_PATHS,
        CMDLINE_LOSSY_PATHS, EXE_LOSSY_PATHS, MAPS_LOSSY_PATHS, STACK_LOSSY_PATHS,
        STATUS_LOSSY_PATHS, STAT_LOSSY_PATHS, WCHAN_LOSSY_PATHS,
    };
    use crate::proc_view::{parse_cgroup, parse_stat, parse_system_cpu};

    #[derive(Debug, Default, Clone, Copy)]
    pub struct LinuxProcSource;

    impl LinuxProcSource {
        pub fn new() -> Self {
            Self
        }
    }

    struct SnapshotReads {
        status: DecodedProcText,
        maps: DecodedProcText,
        wchan: Option<DecodedProcText>,
        cmdline: Vec<u8>,
        nr_fds: u32,
        kernel_stack: Option<DecodedProcText>,
        exe: Option<DecodedProcText>,
        cgroup: Option<DecodedProcText>,
        page_size_bytes: u64,
    }

    impl ProcSource for LinuxProcSource {
        fn snapshot(&self, pid: i32) -> Result<ProcSnapshot, ProcError> {
            let (stat, system) = read_adjacent_cpu_pair(
                || read_required_text(pid, "stat", STAT_LOSSY_PATHS),
                read_system_cpu,
            )?;
            let parsed_stat = parse_stat(&stat.value)?;
            let initial_generation = ProcessGeneration::from(&parsed_stat);
            let reads = with_stable_process_generation(
                pid,
                initial_generation,
                || {
                    let status = read_required_text(pid, "status", STATUS_LOSSY_PATHS)?;
                    let maps = read_required_text(pid, "maps", MAPS_LOSSY_PATHS)?;
                    let wchan = read_optional_text(pid, "wchan", WCHAN_LOSSY_PATHS)?;
                    let cmdline = read_required_bytes(pid, "cmdline")?;
                    let nr_fds = read_fd_count(pid)?;
                    let kernel_stack = if parsed_stat.state == RunState::D {
                        read_optional_text(pid, "stack", STACK_LOSSY_PATHS)?
                    } else {
                        None
                    };
                    let exe = read_exe(pid)?;
                    let cgroup = read_optional_text(pid, "cgroup", CGROUP_LOSSY_PATHS)?;
                    let page_size_bytes = page_size_bytes()?;

                    Ok(SnapshotReads {
                        status,
                        maps,
                        wchan,
                        cmdline,
                        nr_fds,
                        kernel_stack,
                        exe,
                        cgroup,
                        page_size_bytes,
                    })
                },
                || read_process_generation(pid),
            )?;

            let mut degradations = stat.degradations;
            degradations.extend(reads.status.degradations);
            degradations.extend(reads.maps.degradations);
            degradations.extend(invalid_utf8_degradations(
                &reads.cmdline,
                "cmdline",
                CMDLINE_LOSSY_PATHS,
            ));

            let wchan = reads.wchan.map(|text| {
                degradations.extend(text.degradations);
                text.value
            });
            let kernel_stack = reads.kernel_stack.map(|text| {
                degradations.extend(text.degradations);
                text.value
            });
            let exe = reads.exe.map(|text| {
                degradations.extend(text.degradations);
                text.value
            });
            let cgroup = match reads.cgroup {
                Some(text) => {
                    degradations.extend(text.degradations);
                    parse_cgroup(&text.value)?
                }
                None => None,
            };

            Ok(ProcSnapshot {
                stat: stat.value,
                status: reads.status.value,
                maps: reads.maps.value,
                wchan,
                cmdline: reads.cmdline,
                nr_fds: reads.nr_fds,
                kernel_stack,
                exe,
                cgroup,
                degradations,
                system_cpu_ticks: system.ticks,
                logical_cpus: system.logical_cpus,
                page_size_bytes: reads.page_size_bytes,
            })
        }

        fn cpu_counters(&self, pid: i32) -> Result<CpuCounters, ProcError> {
            let (stat, system) = read_adjacent_cpu_pair(
                || read_required_text(pid, "stat", STAT_LOSSY_PATHS),
                read_system_cpu,
            )?;
            let stat = parse_stat(&stat.value)?;
            Ok(CpuCounters {
                process_ticks: stat.process_ticks,
                system_ticks: system.ticks,
                process_start_time_ticks: stat.process_start_time_ticks,
            })
        }
    }

    fn proc_path(pid: i32, leaf: &str) -> PathBuf {
        Path::new("/proc").join(pid.to_string()).join(leaf)
    }

    fn read_required_text(
        pid: i32,
        leaf: &str,
        affected_paths: &[&str],
    ) -> Result<DecodedProcText, ProcError> {
        let path = proc_path(pid, leaf);
        let bytes = fs::read(&path).map_err(|error| map_process_io(error, pid, &path))?;
        Ok(decode_proc_text(&bytes, leaf, affected_paths))
    }

    fn read_required_bytes(pid: i32, leaf: &str) -> Result<Vec<u8>, ProcError> {
        let path = proc_path(pid, leaf);
        fs::read(&path).map_err(|error| map_process_io(error, pid, &path))
    }

    fn read_optional_text(
        pid: i32,
        leaf: &str,
        affected_paths: &[&str],
    ) -> Result<Option<DecodedProcText>, ProcError> {
        let path = proc_path(pid, leaf);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(decode_proc_text(&bytes, leaf, affected_paths))),
            Err(error) if error.kind() == ErrorKind::NotFound => absent_or_gone(pid),
            Err(error) => Err(map_process_io(error, pid, &path)),
        }
    }

    fn read_fd_count(pid: i32) -> Result<u32, ProcError> {
        let path = proc_path(pid, "fd");
        let entries = fs::read_dir(&path).map_err(|error| map_process_io(error, pid, &path))?;
        let mut count = 0_u32;
        for entry in entries {
            entry.map_err(|error| map_process_io(error, pid, &path))?;
            count = count.checked_add(1).ok_or_else(|| ProcError::Parse {
                what: "fd entry".into(),
                reason: "fd 数量超过 u32".into(),
            })?;
        }
        Ok(count)
    }

    fn read_exe(pid: i32) -> Result<Option<DecodedProcText>, ProcError> {
        let path = proc_path(pid, "exe");
        match fs::read_link(&path) {
            Ok(target) => {
                let bytes = target.into_os_string().into_vec();
                Ok(Some(decode_proc_text(&bytes, "exe", EXE_LOSSY_PATHS)))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => absent_or_gone(pid),
            Err(error) => Err(map_process_io(error, pid, &path)),
        }
    }

    fn read_process_generation(pid: i32) -> Result<ProcessGeneration, ProcError> {
        let stat = read_required_text(pid, "stat", STAT_LOSSY_PATHS)?;
        let stat = parse_stat(&stat.value)?;
        Ok(ProcessGeneration::from(&stat))
    }

    fn read_system_cpu() -> Result<crate::proc_view::SystemCpu, ProcError> {
        let path = Path::new("/proc/stat");
        let content = fs::read_to_string(path).map_err(|error| map_global_io(error, path))?;
        parse_system_cpu(&content)
    }

    fn page_size_bytes() -> Result<u64, ProcError> {
        // SAFETY: sysconf is a public libc ABI and _SC_PAGESIZE takes no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(ProcError::InvalidPageSize);
        }
        Ok(page_size as u64)
    }

    fn absent_or_gone<T>(pid: i32) -> Result<Option<T>, ProcError> {
        let proc_dir = Path::new("/proc").join(pid.to_string());
        match fs::metadata(&proc_dir) {
            Ok(_) => Ok(None),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Err(ProcError::ProcNotFound { pid })
            }
            Err(error) => Err(map_process_io(error, pid, &proc_dir)),
        }
    }

    fn map_process_io(error: Error, pid: i32, path: &Path) -> ProcError {
        match classify_proc_io(&error, ProcIoScope::Process) {
            ProcIoErrorClass::ProcNotFound => ProcError::ProcNotFound { pid },
            ProcIoErrorClass::Permission => ProcError::Permission,
            ProcIoErrorClass::InvalidData => ProcError::Parse {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
            ProcIoErrorClass::Other => ProcError::Read {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
        }
    }

    fn map_global_io(error: Error, path: &Path) -> ProcError {
        match classify_proc_io(&error, ProcIoScope::Global) {
            ProcIoErrorClass::Permission => ProcError::Permission,
            ProcIoErrorClass::InvalidData => ProcError::Parse {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
            ProcIoErrorClass::ProcNotFound | ProcIoErrorClass::Other => ProcError::Read {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxProcSource;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Error, ErrorKind};

    use super::*;

    const CAPTURED_STAT: &[u8] = include_bytes!("../tests/fixtures/d7/stat/stat-running.txt");

    fn invalid_utf8_capture() -> Vec<u8> {
        let mut bytes = CAPTURED_STAT.to_vec();
        let comm_start = bytes
            .iter()
            .position(|byte| *byte == b'(')
            .expect("captured stat must contain comm")
            + 1;
        bytes[comm_start] = 0xff;
        bytes
    }

    fn lossy_cases() -> [(
        &'static str,
        &'static [&'static str],
        &'static [&'static str],
    ); 8] {
        [
            ("stat", STAT_LOSSY_PATHS, &["identity.comm"]),
            (
                "status",
                STATUS_LOSSY_PATHS,
                &["identity.uid", "resource.ctxt_switches"],
            ),
            ("maps", MAPS_LOSSY_PATHS, &["mem_shape"]),
            ("wchan", WCHAN_LOSSY_PATHS, &["state.wchan"]),
            ("stack", STACK_LOSSY_PATHS, &["hotspot.frames"]),
            ("cgroup", CGROUP_LOSSY_PATHS, &["identity.cgroup"]),
            ("exe", EXE_LOSSY_PATHS, &["identity.exe"]),
            ("cmdline", CMDLINE_LOSSY_PATHS, &["identity.cmdline"]),
        ]
    }

    #[test]
    fn initial_and_final_cpu_pairs_read_process_then_system_adjacently() {
        let reads = RefCell::new(Vec::new());

        let initial = read_adjacent_cpu_pair(
            || {
                reads.borrow_mut().push("initial_process");
                Ok::<_, ProcError>(10)
            },
            || {
                reads.borrow_mut().push("initial_system");
                Ok::<_, ProcError>(20)
            },
        )
        .unwrap();
        reads.borrow_mut().push("slow_snapshot_read");
        let final_pair = read_adjacent_cpu_pair(
            || {
                reads.borrow_mut().push("final_process");
                Ok::<_, ProcError>(30)
            },
            || {
                reads.borrow_mut().push("final_system");
                Ok::<_, ProcError>(40)
            },
        )
        .unwrap();

        assert_eq!(initial, (10, 20));
        assert_eq!(final_pair, (30, 40));
        assert_eq!(
            reads.into_inner(),
            [
                "initial_process",
                "initial_system",
                "slow_snapshot_read",
                "final_process",
                "final_system",
            ]
        );
    }

    #[test]
    fn invalid_utf8_is_replaced_and_mapped_to_every_affected_level0_path() {
        let invalid = invalid_utf8_capture();

        for (what, configured_paths, expected_paths) in lossy_cases() {
            let decoded = decode_proc_text(&invalid, what, configured_paths);

            assert!(decoded.value.contains('\u{fffd}'), "{what}");
            assert_eq!(decoded.degradations.len(), expected_paths.len(), "{what}");
            let actual_paths = decoded
                .degradations
                .iter()
                .map(|degradation| degradation.path.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual_paths, expected_paths, "{what}");
            for degradation in &decoded.degradations {
                assert!(degradation.reason.contains(what), "{what}");
                assert!(degradation.reason.contains("U+FFFD"), "{what}");
            }
        }
    }

    #[test]
    fn ordinary_utf8_is_preserved_and_emits_no_degradation() {
        for (what, configured_paths, _) in lossy_cases() {
            let decoded = decode_proc_text(CAPTURED_STAT, what, configured_paths);

            assert_eq!(decoded.value.as_bytes(), CAPTURED_STAT, "{what}");
            assert!(decoded.degradations.is_empty(), "{what}");
        }
    }

    #[test]
    fn genuine_replacement_character_is_valid_utf8_and_emits_no_degradation() {
        let captured = std::str::from_utf8(CAPTURED_STAT).expect("captured stat is valid UTF-8");
        let valid = format!("{captured}\u{fffd}");

        for (what, configured_paths, _) in lossy_cases() {
            let decoded = decode_proc_text(valid.as_bytes(), what, configured_paths);

            assert!(decoded.value.ends_with('\u{fffd}'), "{what}");
            assert!(decoded.degradations.is_empty(), "{what}");
        }
    }

    #[test]
    fn snapshot_generation_change_after_body_is_proc_not_found() {
        let stat = crate::proc_view::parse_stat(
            std::str::from_utf8(CAPTURED_STAT).expect("captured stat is valid UTF-8"),
        )
        .expect("captured stat must parse");
        let initial = ProcessGeneration::from(&stat);
        let reads = RefCell::new(Vec::new());

        let error = with_stable_process_generation(
            initial.pid,
            initial,
            || {
                reads.borrow_mut().push("snapshot");
                Ok::<_, ProcError>(())
            },
            || {
                reads.borrow_mut().push("final_stat");
                Ok(ProcessGeneration {
                    start_time_ticks: initial.start_time_ticks + 1,
                    ..initial
                })
            },
        )
        .expect_err("mid-snapshot PID generation change must fail");

        assert_eq!(error, ProcError::ProcNotFound { pid: initial.pid });
        assert_eq!(reads.into_inner(), ["snapshot", "final_stat"]);
    }

    #[test]
    fn snapshot_pid_change_after_body_is_proc_not_found() {
        let stat = crate::proc_view::parse_stat(
            std::str::from_utf8(CAPTURED_STAT).expect("captured stat is valid UTF-8"),
        )
        .expect("captured stat must parse");
        let initial = ProcessGeneration::from(&stat);

        let error = with_stable_process_generation(
            initial.pid,
            initial,
            || Ok::<_, ProcError>(()),
            || {
                Ok(ProcessGeneration {
                    pid: initial.pid + 1,
                    ..initial
                })
            },
        )
        .expect_err("mid-snapshot PID change must fail");

        assert_eq!(error, ProcError::ProcNotFound { pid: initial.pid });
    }

    #[test]
    fn matching_snapshot_generation_succeeds_after_final_stat_read() {
        let stat = crate::proc_view::parse_stat(
            std::str::from_utf8(CAPTURED_STAT).expect("captured stat is valid UTF-8"),
        )
        .expect("captured stat must parse");
        let initial = ProcessGeneration::from(&stat);
        let reads = RefCell::new(Vec::new());

        let value = with_stable_process_generation(
            initial.pid,
            initial,
            || {
                reads.borrow_mut().push("snapshot");
                Ok::<_, ProcError>("complete")
            },
            || {
                reads.borrow_mut().push("final_stat");
                Ok(initial)
            },
        )
        .expect("matching PID generation must succeed");

        assert_eq!(value, "complete");
        assert_eq!(reads.into_inner(), ["snapshot", "final_stat"]);
    }

    #[test]
    fn process_io_maps_not_found_and_esrch_to_proc_not_found() {
        for error in [
            Error::new(ErrorKind::NotFound, "gone"),
            Error::from_raw_os_error(ESRCH_RAW_OS_ERROR),
        ] {
            assert_eq!(
                classify_proc_io(&error, ProcIoScope::Process),
                ProcIoErrorClass::ProcNotFound
            );
        }
    }

    #[test]
    fn process_io_keeps_global_and_unrelated_errors_distinct_from_disappearance() {
        for (error, expected) in [
            (
                Error::new(ErrorKind::PermissionDenied, "denied"),
                ProcIoErrorClass::Permission,
            ),
            (
                Error::new(ErrorKind::InvalidData, "invalid"),
                ProcIoErrorClass::InvalidData,
            ),
            (Error::other("unrelated"), ProcIoErrorClass::Other),
        ] {
            assert_eq!(classify_proc_io(&error, ProcIoScope::Process), expected);
        }

        for error in [
            Error::new(ErrorKind::NotFound, "global path missing"),
            Error::from_raw_os_error(ESRCH_RAW_OS_ERROR),
        ] {
            assert_eq!(
                classify_proc_io(&error, ProcIoScope::Global),
                ProcIoErrorClass::Other
            );
        }
    }
}
