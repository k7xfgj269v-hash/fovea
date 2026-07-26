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

/// The two counters used by the short CPU sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCounters {
    pub process_ticks: u64,
    pub system_ticks: u64,
}

/// Structured procfs failure modes.
#[derive(Debug, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcError {
    #[error("pid {pid} 不存在")]
    ProcNotFound { pid: i32 },
    #[error("读 /proc 权限不足")]
    Permission,
    #[error("读取 {what} 失败：{reason}")]
    Read { what: String, reason: String },
    #[error("解析 {what} 失败：{reason}")]
    Parse { what: String, reason: String },
    #[error("尚未实现（M1 第二刀）")]
    NotImplemented,
}

impl ProcError {
    pub fn to_error_report(&self) -> (&'static str, String, Option<&'static str>) {
        match self {
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
            ProcError::Read { what, reason } => (
                "proc_read_failed",
                format!("读取 {what} 失败：{reason}"),
                Some("确认 procfs 已挂载且目标内核暴露所需文件"),
            ),
            ProcError::Parse { what, reason } => (
                "proc_parse_failed",
                format!("解析 {what} 失败：{reason}"),
                Some("大概率是 /proc 行格式漂移；对齐到目标内核版本"),
            ),
            ProcError::NotImplemented => (
                "not_implemented",
                "introspect 该路径尚未在当前 milestone 实现".into(),
                None,
            ),
        }
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

    use super::{CpuCounters, ProcError, ProcSnapshot, ProcSource};
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
            let stat = read_required_string(pid, "stat")?;
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
            let system = read_system_cpu()?;
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
            let stat = parse_stat(&read_required_string(pid, "stat")?)?;
            let system = read_system_cpu()?;
            Ok(CpuCounters {
                process_ticks: stat.process_ticks,
                system_ticks: system.ticks,
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
            return Err(ProcError::Parse {
                what: "sysconf(_SC_PAGESIZE)".into(),
                reason: format!("返回无效页大小 {page_size}"),
            });
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
        match error.kind() {
            ErrorKind::NotFound => ProcError::ProcNotFound { pid },
            ErrorKind::PermissionDenied => ProcError::Permission,
            ErrorKind::InvalidData => ProcError::Parse {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
            _ => ProcError::Read {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
        }
    }

    fn map_global_io(error: Error, path: &Path) -> ProcError {
        match error.kind() {
            ErrorKind::PermissionDenied => ProcError::Permission,
            ErrorKind::InvalidData => ProcError::Parse {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
            _ => ProcError::Read {
                what: path.display().to_string(),
                reason: error.to_string(),
            },
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxProcSource;
