//! `/proc` access ports and the Linux procfs adapter.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// All procfs inputs needed to assemble one Level 0 result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnapshot {
    pub stat: String,
    pub status: String,
    pub maps: String,
    pub wchan: Option<String>,
    pub cmdline: Vec<u8>,
    pub fd_names: Vec<String>,
    pub kernel_stack: Option<String>,
    pub exe: Option<String>,
    pub cgroup: Option<String>,
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
    use std::ffi::OsString;
    use std::fs;
    use std::io::{Error, ErrorKind};
    use std::path::{Path, PathBuf};

    use introspect_schema::RunState;

    use super::{
        classify_proc_io, read_adjacent_cpu_pair, CpuCounters, ProcError, ProcIoErrorClass,
        ProcIoScope, ProcSnapshot, ProcSource,
    };
    use crate::proc_view::{parse_cgroup, parse_stat, parse_system_cpu};

    #[derive(Debug, Default, Clone, Copy)]
    pub struct LinuxProcSource;

    impl LinuxProcSource {
        pub fn new() -> Self {
            Self
        }
    }

    impl ProcSource for LinuxProcSource {
        fn snapshot(&self, pid: i32) -> Result<ProcSnapshot, ProcError> {
            let (stat, system) = read_adjacent_cpu_pair(
                || read_required_string(pid, "stat"),
                read_system_cpu,
            )?;
            let parsed_stat = parse_stat(&stat)?;
            let status = read_required_string(pid, "status")?;
            let maps = read_required_string(pid, "maps")?;
            let wchan = read_optional_string(pid, "wchan")?;
            let cmdline = read_required_bytes(pid, "cmdline")?;
            let fd_names = read_fd_names(pid)?;
            let kernel_stack = if parsed_stat.state == RunState::D {
                read_optional_string(pid, "stack")?
            } else {
                None
            };
            let exe = read_exe(pid)?;
            let cgroup = match read_optional_string(pid, "cgroup")? {
                Some(content) => parse_cgroup(&content)?,
                None => None,
            };
            let page_size_bytes = page_size_bytes()?;

            Ok(ProcSnapshot {
                stat,
                status,
                maps,
                wchan,
                cmdline,
                fd_names,
                kernel_stack,
                exe,
                cgroup,
                system_cpu_ticks: system.ticks,
                logical_cpus: system.logical_cpus,
                page_size_bytes,
            })
        }

        fn cpu_counters(&self, pid: i32) -> Result<CpuCounters, ProcError> {
            let (stat, system) = read_adjacent_cpu_pair(
                || read_required_string(pid, "stat"),
                read_system_cpu,
            )?;
            let stat = parse_stat(&stat)?;
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

    fn read_required_string(pid: i32, leaf: &str) -> Result<String, ProcError> {
        let path = proc_path(pid, leaf);
        fs::read_to_string(&path).map_err(|error| map_process_io(error, pid, &path))
    }

    fn read_required_bytes(pid: i32, leaf: &str) -> Result<Vec<u8>, ProcError> {
        let path = proc_path(pid, leaf);
        fs::read(&path).map_err(|error| map_process_io(error, pid, &path))
    }

    fn read_optional_string(pid: i32, leaf: &str) -> Result<Option<String>, ProcError> {
        let path = proc_path(pid, leaf);
        match fs::read_to_string(&path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == ErrorKind::NotFound => absent_or_gone(pid),
            Err(error) => Err(map_process_io(error, pid, &path)),
        }
    }

    fn read_fd_names(pid: i32) -> Result<Vec<String>, ProcError> {
        let path = proc_path(pid, "fd");
        let entries = fs::read_dir(&path).map_err(|error| map_process_io(error, pid, &path))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| map_process_io(error, pid, &path))?;
            names.push(os_string_to_utf8(entry.file_name(), "fd entry")?);
        }
        Ok(names)
    }

    fn read_exe(pid: i32) -> Result<Option<String>, ProcError> {
        let path = proc_path(pid, "exe");
        match fs::read_link(&path) {
            Ok(target) => os_string_to_utf8(target.into_os_string(), "exe").map(Some),
            Err(error) if error.kind() == ErrorKind::NotFound => absent_or_gone(pid),
            Err(error) => Err(map_process_io(error, pid, &path)),
        }
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

    fn os_string_to_utf8(value: OsString, what: &str) -> Result<String, ProcError> {
        value.into_string().map_err(|value| ProcError::Parse {
            what: what.into(),
            reason: format!("非 UTF-8 路径：{value:?}"),
        })
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

    #[test]
    fn cpu_pair_reads_process_then_system_without_intervening_reads() {
        let reads = RefCell::new(Vec::new());

        let pair = read_adjacent_cpu_pair(
            || {
                reads.borrow_mut().push("process");
                Ok::<_, ProcError>(10)
            },
            || {
                reads.borrow_mut().push("system");
                Ok::<_, ProcError>(20)
            },
        )
        .unwrap();
        reads.borrow_mut().push("slow_snapshot_read");

        assert_eq!(pair, (10, 20));
        assert_eq!(
            reads.into_inner(),
            ["process", "system", "slow_snapshot_read"]
        );
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
    fn process_io_keeps_unrelated_errors_non_disappearance() {
        let unrelated = Error::new(ErrorKind::Other, "unrelated");
        assert_eq!(
            classify_proc_io(&unrelated, ProcIoScope::Process),
            ProcIoErrorClass::Other
        );

        for error in [
            Error::new(ErrorKind::NotFound, "global path missing"),
            Error::from_raw_os_error(ESRCH_RAW_OS_ERROR),
        ] {
            assert_ne!(
                classify_proc_io(&error, ProcIoScope::Global),
                ProcIoErrorClass::ProcNotFound
            );
        }
    }
}
