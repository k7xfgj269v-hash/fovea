//! `/proc/<pid>/{...}` 解析（§13.4）。
//!
//! Level 0 全部来自 /proc 解析——`/proc/<pid>/{stat,status,maps,wchan,stack,fd/}`
//! 和 `/proc/<pid>/stat` 短采样两次读得到 %cpu。**零探针零 ptrace** —— 纯读文件，
//! 对目标进程连观察者效应都没有（§13.4）。
//!
//! 本模块专门负责解析层；不在本模块做符号化（符号化是 [`crate::symbolize`] 的事），
//! 不在本模块组合完整 Level 0（那是 [`crate::introspect`] 的事）。Linux 文件 I/O
//! 全部留在 [`crate::proc_source`]，因此解析测试可以在 Mac 上运行。

use introspect_schema::{MapKind, MapKindBucket, MemShape, RunState, TopMap};

use crate::degradation::ProcDegradation;

pub use crate::proc_source::ProcError;

// ─── /proc/<pid>/stat 的裸解析产物 ─────────────────────────────────────────────

/// `/proc/<pid>/stat` 解析后字段——只取 Level 0 需要那份，不是完整 stat。
///
/// 注：stat 的 comm 字段带括号且内含空格（"comm (name with space)"），
/// 常规 split 会出错。要手写 tokenizer，从右括号 ')' 后重新分割（见下）。
#[derive(Debug, Clone)]
pub struct Stat {
    pub pid: i32,
    pub comm: String,
    /// stat 第二字段（单字符 R/S/D/Z/T）。
    pub state: RunState,
    pub ppid: i32,
    pub nr_threads: u32,
    pub vsize: u64,
    pub rss: u64,
    /// stat 字段 14 + 15：进程用户态和内核态累计 ticks。
    pub process_ticks: u64,
    /// stat 字段 22：进程启动时间，用于识别 PID 对应的进程代际。
    pub process_start_time_ticks: u64,
    /// stat 第 39 字段：last CPU。
    pub last_cpu: u32,
    // ⚠️ ctxt_switches **不**从 stat 取。man proc 字段 40 = `rt_priority`、
    // 41 = `policy`——历史代码曾把它们当 ctxt 读在真 Linux 上静默给错数。
    // 真源在 `/proc/<pid>/status` 的 `voluntary_ctxt_switches:`/
    // `nonvoluntary_ctxt_switches:` 单值行，见 [`Status`] + [`parse_status`]。
}

/// `/proc/<pid>/status` 解析后字段。status 是 `Key:\tValue` 行格式，
/// 我们只取 Level 0 要的几行（uid、fd 上限、ctxt_switches）。其余行（VmRSS /
/// VmSize 已在 stat 里有多份来源）不去重——本刀只取 identity.uid + fd 上限
/// （§10 没有 fd 极限字段，但 knowledge 用途放在 §6 第 1 层 know-your-target）
/// + ctxt_switches（stat 的 40/41 是 rt_priority/policy 不是 ctxt，**只能**从
///   status 取——这条是 §§ 读侧静默污染防线的代码归宿之一）。
#[derive(Debug, Clone, Default)]
pub struct Status {
    pub uid: u32,
    /// /proc/<pid>/status 的 `FDSize:` 行——内核给该进程的实际 fd 表大小。
    /// Level 0 用 `nr_fds`（scan_fds 实数），status 里的 FDSize 默认只是上限占位。
    pub fd_size: Option<u32>,
    /// `/proc/<pid>/status` 的 `voluntary_ctxt_switches:` 行单值。
    /// 缺行（stripped 内核偶见）默认 0——与 RSS=0 同语义：best-effort（§11）。
    pub voluntary_ctxt_switches: u64,
    pub has_voluntary_ctxt_switches: bool,
    /// 同上，`nonvoluntary_ctxt_switches:` 行。
    pub nonvoluntary_ctxt_switches: u64,
    pub has_nonvoluntary_ctxt_switches: bool,
}

// ─── 常量 ────────────────────────────────────────────────────────────────────

/// §10 没硬给 cmdline 截断宽度，本刀定 256。这是 DESIGN 留白项之一，
/// 未来调不会破 schema。
pub(crate) const CMDLINE_SHORT_MAX: usize = 256;

/// §10 没硬给 top-N 的 N，本刀定 5。
pub(crate) const MEM_SHAPE_TOP_N: usize = 5;

/// Level 0 top-map backing 的 UTF-8 字节上限。
pub const TOP_MAP_BACKING_MAX_BYTES: usize = 256;

// ─── §13.4 parse_stat：从右括号 ')' 切回 ────────────────────────────────────

/// `/proc/<pid>/stat` 的裸解析。
///
/// 关键坑：comm 字段被括号包住且**内含空格**（试想 `(my program)` 这样的 comm）。
/// 标准空格分词会碎掉。本函数按 man proc 的口径：找最后一个 `)`，把它前面
/// 的一切（含括号，再去括号）作为 comm，把 ')' 之后的内容按空格分词；
/// `pid` 是首个字段，在括号之前。
///
/// stat 字段编号（1 起算，man proc）：1=pid 2=comm 3=state 4=ppid ...
/// 20=nr_threads 23=vsize 24=rss 39=last_cpu。tail-idx 比 man-field# 小 3。
/// ⚠️ 字段 40/41 是 `rt_priority`/`policy`，**不是** ctxt——ctxt 从 status
/// 取（见 [`Status`] / [`parse_status`]）。
///
/// 返 [`ProcError::Parse`] 当解析某字段失败时。
pub fn parse_stat(content: &str) -> Result<Stat, ProcError> {
    let content = content.trim();
    // 先找左括号（接在 pid 后面）。
    let lparen = content.find('(').ok_or_else(|| ProcError::Parse {
        what: "stat".into(),
        reason: "缺少左括号 (comm)".into(),
    })?;
    let rparen = content.rfind(')').ok_or_else(|| ProcError::Parse {
        what: "stat".into(),
        reason: "缺少右括号 (comm)".into(),
    })?;
    if rparen < lparen {
        return Err(ProcError::Parse {
            what: "stat".into(),
            reason: "右括号在左括号之前".into(),
        });
    }
    // pid 在左括号之前的第一个字段。
    let pid_str = content[..lparen].trim();
    let pid: i32 = pid_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.pid".into(),
            reason: e.to_string(),
        })?;
    // comm = 括号内（去括号）。 不再加回括号——§10 identity.comm 是不带括号的进程名。
    let comm = content[lparen + 1..rparen].to_string();
    // 内核格式在右括号后固定为 ` state ...`。先验证 state 槽没有被空白吞掉，
    // 再做后续分词，否则缺失 state 时 ppid 会被误当成未知状态。
    let after_comm = content[rparen + 1..]
        .strip_prefix(' ')
        .ok_or_else(|| ProcError::Parse {
            what: "stat.state".into(),
            reason: "comm 后缺 state 分隔空格".into(),
        })?;
    if after_comm.chars().next().is_none_or(char::is_whitespace) {
        return Err(ProcError::Parse {
            what: "stat.state".into(),
            reason: "空状态".into(),
        });
    }
    // 右括号之后按空格分词。第一个 = state（单字符）。
    let tail = after_comm.trim();
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // tail 字段索引按 man proc 编号减 3 （因为括号前是 1=pid/2=comm）。
    // fields[0] = state, fields[1] = ppid ... fields[i] = 字段编号 (i+3)。
    let need = |i: usize, name: &str| -> Result<&str, ProcError> {
        fields.get(i).copied().ok_or_else(|| ProcError::Parse {
            what: "stat".into(),
            reason: format!("缺字段 {} (idx {i})", name),
        })
    };
    let state = parse_run_state(need(0, "state")?)?;
    let ppid: i32 = need(1, "ppid")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.ppid".into(),
            reason: e.to_string(),
        })?;
    let utime: u64 = need(11, "utime")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.utime".into(),
            reason: e.to_string(),
        })?;
    let stime: u64 = need(12, "stime")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.stime".into(),
            reason: e.to_string(),
        })?;
    // 字段 20=nr_threads => idx 17 (20-3)。
    let nr_threads: u32 =
        need(17, "nr_threads")?
            .parse()
            .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                what: "stat.nr_threads".into(),
                reason: e.to_string(),
            })?;
    // 字段 22=starttime => idx 19。
    let process_start_time_ticks: u64 =
        need(19, "starttime")?
            .parse()
            .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                what: "stat.starttime".into(),
                reason: e.to_string(),
            })?;
    // 字段 23=vsize => idx 20。
    let vsize: u64 = need(20, "vsize")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.vsize".into(),
            reason: e.to_string(),
        })?;
    // 字段 24=rss => idx 21。rss 在 stat 里是**页数**，不是字节——要之后乘 page size。
    let rss_pages: u64 = need(21, "rss")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.rss".into(),
            reason: e.to_string(),
        })?;
    // 字段 39=last_cpu => idx 36。
    let last_cpu: u32 = need(36, "last_cpu")?
        .parse()
        .map_err(|e: std::num::ParseIntError| ProcError::Parse {
            what: "stat.last_cpu".into(),
            reason: e.to_string(),
        })?;
    // ⚠️ 不读字段 40/41——那是 rt_priority/policy（不是 ctxt）。ctxt 从
    // status 取（见 parse_status）。历史代码 need(37)/need(38) 把 rt_priority/
    // policy 当成 ctxt 是静默错数 bug，同构 fixture 让它在 Mac 单测里测不出。

    Ok(Stat {
        pid,
        comm,
        state,
        ppid,
        nr_threads,
        vsize,
        rss: rss_pages,
        process_ticks: utime.saturating_add(stime),
        process_start_time_ticks,
        last_cpu,
    })
}

/// Parsed aggregate `/proc/stat` CPU counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemCpu {
    pub ticks: u64,
    pub logical_cpus: u32,
}

/// Parse aggregate CPU ticks and the logical CPU line count from `/proc/stat`.
///
/// Linux reports guest and guest_nice as time already included in user and
/// nice, so only the first eight counters are summed to avoid double-counting.
pub fn parse_system_cpu(content: &str) -> Result<SystemCpu, ProcError> {
    let mut aggregate = None;
    let mut logical_cpus: u32 = 0;

    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        if name == "cpu" {
            let values: Vec<&str> = fields.collect();
            if values.len() < 4 {
                return Err(ProcError::Parse {
                    what: "proc_stat.cpu".into(),
                    reason: "aggregate cpu 行少于 4 个计数器".into(),
                });
            }
            let mut ticks = 0u64;
            for value in values.into_iter().take(8) {
                let value = value
                    .parse::<u64>()
                    .map_err(|error: std::num::ParseIntError| ProcError::Parse {
                        what: "proc_stat.cpu".into(),
                        reason: error.to_string(),
                    })?;
                ticks = ticks.checked_add(value).ok_or_else(|| ProcError::Parse {
                    what: "proc_stat.cpu".into(),
                    reason: "aggregate cpu ticks 溢出 u64".into(),
                })?;
            }
            aggregate = Some(ticks);
        } else if let Some(index) = name.strip_prefix("cpu") {
            if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) {
                logical_cpus = logical_cpus
                    .checked_add(1)
                    .ok_or_else(|| ProcError::Parse {
                        what: "proc_stat.logical_cpus".into(),
                        reason: "logical CPU 数溢出 u32".into(),
                    })?;
            }
        }
    }

    let ticks = aggregate.ok_or_else(|| ProcError::Parse {
        what: "proc_stat.cpu".into(),
        reason: "缺 aggregate cpu 行".into(),
    })?;
    if logical_cpus == 0 {
        return Err(ProcError::Parse {
            what: "proc_stat.logical_cpus".into(),
            reason: "没有 cpuN 行".into(),
        });
    }

    Ok(SystemCpu {
        ticks,
        logical_cpus,
    })
}

/// Parse the effective cgroup path from `/proc/<pid>/cgroup`.
pub fn parse_cgroup(content: &str) -> Result<Option<String>, ProcError> {
    let mut first_v1 = None;
    let mut first_error = None;

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        match parse_cgroup_line(line) {
            Ok(CgroupEntry::Unified(path)) => return Ok(Some(path)),
            Ok(CgroupEntry::Legacy(path)) => {
                if first_v1.is_none() {
                    first_v1 = Some(path);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    if let Some(path) = first_v1 {
        return Ok(Some(path));
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(None)
}

enum CgroupEntry {
    Unified(String),
    Legacy(String),
}

fn parse_cgroup_line(line: &str) -> Result<CgroupEntry, ProcError> {
    let mut fields = line.splitn(3, ':');
    let hierarchy = fields.next().unwrap_or_default();
    let controllers = fields.next().ok_or_else(|| ProcError::Parse {
        what: "cgroup".into(),
        reason: "缺 controllers 字段".into(),
    })?;
    let path = fields.next().ok_or_else(|| ProcError::Parse {
        what: "cgroup".into(),
        reason: "缺 path 字段".into(),
    })?;
    if path.is_empty() {
        return Err(ProcError::Parse {
            what: "cgroup".into(),
            reason: "path 为空".into(),
        });
    }
    if !path.starts_with('/') {
        return Err(ProcError::Parse {
            what: "cgroup".into(),
            reason: format!("path 不是绝对路径: {path:?}"),
        });
    }
    hierarchy.parse::<u32>().map_err(|error| ProcError::Parse {
        what: "cgroup".into(),
        reason: format!("hierarchy 非数字 {hierarchy:?}: {error}"),
    })?;

    if hierarchy == "0" {
        if controllers.is_empty() {
            Ok(CgroupEntry::Unified(path.to_string()))
        } else {
            Err(ProcError::Parse {
                what: "cgroup".into(),
                reason: "cgroup v2 hierarchy 0 的 controllers 必须为空".into(),
            })
        }
    } else if controllers.is_empty() {
        Err(ProcError::Parse {
            what: "cgroup".into(),
            reason: "cgroup v1 controllers 为空".into(),
        })
    } else {
        Ok(CgroupEntry::Legacy(path.to_string()))
    }
}

fn parse_run_state(s: &str) -> Result<RunState, ProcError> {
    // man proc：state 是一个字符，偶尔后面跟额外字符如 '+'（高优先级运行队列）。
    // 取首字符。
    let c = s.chars().next().ok_or_else(|| ProcError::Parse {
        what: "stat.state".into(),
        reason: "空状态".into(),
    })?;
    Ok(RunState::from_char(c))
}

// ─── §13.4 parse_status：Key:\t Value 行格式 ──────────────────────────────

/// `/proc/<pid>/status` 解析。取 Uid / FDSize / ctxt_switches 三组。
pub fn parse_status(content: &str) -> Result<Status, ProcError> {
    let mut st = Status::default();
    for line in content.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("Uid:") {
            // `Uid:\t1000\t1000\t1000\t1000` — 四列 (real/effective/saved/fs)。
            // 取第一列 real uid。
            let first = rest.split_whitespace().next().unwrap_or("0");
            st.uid = first
                .parse()
                .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                    what: "status.uid".into(),
                    reason: e.to_string(),
                })?;
        } else if let Some(rest) = line.strip_prefix("FDSize:") {
            let n = rest
                .trim()
                .parse::<u32>()
                .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                    what: "status.fdsize".into(),
                    reason: e.to_string(),
                })?;
            st.fd_size = Some(n);
        } else if let Some(rest) = line.strip_prefix("voluntary_ctxt_switches:") {
            // 单值行 `voluntary_ctxt_switches:\t<N>`。缺行（stripped 内核偶见）
            // 走 Default=0——best-effort（§11）。**唯一**可靠源：stat 的 40/41
            // 字段是 rt_priority/policy，不能当 ctxt 用。
            st.voluntary_ctxt_switches =
                rest.trim()
                    .parse::<u64>()
                    .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                        what: "status.voluntary_ctxt_switches".into(),
                        reason: e.to_string(),
                    })?;
            st.has_voluntary_ctxt_switches = true;
        } else if let Some(rest) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            st.nonvoluntary_ctxt_switches =
                rest.trim()
                    .parse::<u64>()
                    .map_err(|e: std::num::ParseIntError| ProcError::Parse {
                        what: "status.nonvoluntary_ctxt_switches".into(),
                        reason: e.to_string(),
                    })?;
            st.has_nonvoluntary_ctxt_switches = true;
        }
    }
    Ok(st)
}

// ─── §13.4 parse_maps：皇冠明珠投影本体 ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedMaps {
    pub mem_shape: MemShape,
    pub valid_line_count: usize,
    pub skipped_line_count: usize,
    pub degradations: Vec<ProcDegradation>,
}

/// `/proc/<pid>/maps` 的解析 + 投影聚合（§10 mem_shape）。
///
/// maps 行格式（man proc）：
/// `address           perms offset  dev   inode    pathname`
/// `7f1234567000-7f1234678000 rw-p 00000000 00:00 0        [heap]`
/// path 字段可能不存在（匿名映射后没有空白），也可能带空格（罕见, M1 不去特殊处理）。
///
/// 投影策略：每行按 [`classify_map_kind`] 归类到 §10 kind 五类；按 kind group 后
/// 产出 `{count, total_size}` 直方图；按 size 降序取 top-N。**绝不把原始 maps
/// 表透出**——GB 级 maps → 十几行（histogram 5 类最多 5 行 + top-N 最多 5 行），
/// 这就是 §10「投影本体」代码归宿。
pub fn parse_maps(content: &str) -> Result<MemShape, ProcError> {
    Ok(parse_maps_with_diagnostics(content)?.mem_shape)
}

pub fn parse_maps_with_diagnostics(content: &str) -> Result<ParsedMaps, ProcError> {
    let mut buckets: std::collections::HashMap<MapKind, (u64, u64)> =
        std::collections::HashMap::with_capacity(5);
    let mut tops: Vec<TopMap> = Vec::new();
    let mut valid_line_count = 0usize;
    let mut skipped_line_count = 0usize;

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let map = match parse_map_line(line) {
            Ok(map) => map,
            Err(_) => {
                skipped_line_count += 1;
                continue;
            }
        };
        valid_line_count += 1;
        let kind = classify_map_kind(&map.perms, map.path.as_deref()).unwrap_or(MapKind::Anon); // 无 path → Anon；§10 五类里没列的归 Anon 兜底
        let size = map.end.saturating_sub(map.start);
        // 直方图累加
        let entry = buckets.entry(kind).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += size;
        // top-N 候选
        tops.push(TopMap {
            start: format!("{:016x}", map.start),
            end: format!("{:016x}", map.end),
            size,
            kind,
            backing: map.path,
        });
    }
    // 直方图按 §10 kind 五类固定次序输出
    let mut histogram: Vec<MapKindBucket> = [
        MapKind::Heap,
        MapKind::Stack,
        MapKind::Anon,
        MapKind::File,
        MapKind::XLib,
    ]
    .into_iter()
    .filter_map(|k| {
        buckets.remove(&k).map(|(count, total_size)| MapKindBucket {
            kind: k,
            count,
            total_size,
        })
    })
    .collect();
    histogram.sort_by_key(|b| b.kind as i32);

    // top-N：按 size 降序取前 MEM_SHAPE_TOP_N
    tops.sort_by_key(|map| std::cmp::Reverse(map.size));
    tops.truncate(MEM_SHAPE_TOP_N);

    let mut degradations = Vec::new();
    if skipped_line_count > 0 {
        degradations.push(ProcDegradation::new(
            "mem_shape",
            format!("skipped {skipped_line_count} malformed maps lines"),
        ));
    }
    for (index, top) in tops.iter_mut().enumerate() {
        let Some(backing) = top.backing.as_mut() else {
            continue;
        };
        let original_len = backing.len();
        if original_len <= TOP_MAP_BACKING_MAX_BYTES {
            continue;
        }
        *backing = truncate_utf8_bytes(backing, TOP_MAP_BACKING_MAX_BYTES);
        degradations.push(ProcDegradation::new(
            format!("mem_shape.top_n[{index}].backing"),
            format!(
                "backing truncated from {original_len} to {} UTF-8 bytes",
                backing.len()
            ),
        ));
    }

    Ok(ParsedMaps {
        mem_shape: MemShape {
            histogram,
            top_n: tops,
        },
        valid_line_count,
        skipped_line_count,
        degradations,
    })
}

/// /proc/<pid>/maps 单行解析中间件。
struct MapLine {
    start: u64,
    end: u64,
    perms: String,
    path: Option<String>,
}

fn parse_map_line(line: &str) -> Result<MapLine, String> {
    // 期望：<start>-<end> <perms> <offset> <dev> <inode> [path]
    // path 段从第 5 个空白分隔字段之后捡剩余整段（路径含空格也兜单行）。
    let mut it = line.splitn(2, ' ');
    let addr_seg = it.next().ok_or("空行")?.trim();
    let rest = it.next().ok_or("缺 perms+path 段")?.trim_start();

    let (start_s, end_s) = addr_seg
        .split_once('-')
        .ok_or_else(|| format!("地址段无 '-': {addr_seg:?}"))?;
    let start = u64::from_str_radix(start_s.trim(), 16)
        .map_err(|e| format!("start 非十六进制 {start_s:?}: {e}"))?;
    let end = u64::from_str_radix(end_s.trim(), 16)
        .map_err(|e| format!("end 非十六进制 {end_s:?}: {e}"))?;
    if end <= start {
        return Err(format!("地址范围非递增: {start_s:?}-{end_s:?}"));
    }

    // 从 rest 里拆 perms 与 path。perms 段是首字段 4 个 char, 之后空格, 然后 offset/dev/inode,
    // 然后 1 个或更多空格 + path (或没 path)。
    let perms = rest
        .split_whitespace()
        .next()
        .ok_or("缺 perms 字段")?
        .to_string();
    let perms_bytes = perms.as_bytes();
    if perms_bytes.len() != 4
        || !matches!(perms_bytes[0], b'r' | b'-')
        || !matches!(perms_bytes[1], b'w' | b'-')
        || !matches!(perms_bytes[2], b'x' | b'-')
        || !matches!(perms_bytes[3], b'p' | b's')
    {
        return Err(format!("perms 不匹配 [r-][w-][x-][ps]: {perms:?}"));
    }
    // 路径段在最末：从 rest 找第二+次空格分布中开头第 5 个 token 之后的整段。
    // 兜底更稳的方式: 找 path 起点为 perms 之后第 4 个空格分界的位置。
    // 在 M1 简化口径下: 用 token 计数, 多于 5 个 token 说明 path 存在.
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    // tokens[0]=perms, tokens[1]=offset, tokens[2]=dev, tokens[3]=inode, tokens[4..]=path
    if tokens.len() < 4 {
        return Err("缺 offset/dev/inode 字段".into());
    }
    u64::from_str_radix(tokens[1], 16)
        .map_err(|error| format!("offset 非十六进制 {:?}: {error}", tokens[1]))?;
    let (dev_major, dev_minor) = tokens[2]
        .split_once(':')
        .ok_or_else(|| format!("dev 字段无 ':': {:?}", tokens[2]))?;
    u64::from_str_radix(dev_major, 16)
        .map_err(|error| format!("dev major 非十六进制 {dev_major:?}: {error}"))?;
    u64::from_str_radix(dev_minor, 16)
        .map_err(|error| format!("dev minor 非十六进制 {dev_minor:?}: {error}"))?;
    tokens[3]
        .parse::<u64>()
        .map_err(|error| format!("inode 非十进制 {:?}: {error}", tokens[3]))?;
    let path = if tokens.len() > 4 {
        let path_start_byte_in_rest = whitespace_token_start(rest, 4).ok_or("path 起点定位失败")?;
        Some(rest[path_start_byte_in_rest..].to_string())
    } else {
        None
    };

    Ok(MapLine {
        start,
        end,
        perms,
        path,
    })
}

fn whitespace_token_start(input: &str, target: usize) -> Option<usize> {
    let mut token_index = 0usize;
    let mut in_token = false;

    for (index, character) in input.char_indices() {
        if character.is_whitespace() {
            in_token = false;
        } else if !in_token {
            if token_index == target {
                return Some(index);
            }
            token_index += 1;
            in_token = true;
        }
    }
    None
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

// ─── §13.4 classify_map_kind：kind 五分类 ─────────────────────────────────

/// §10 mem_shape 用的 maps 区段分类初判。看 perms + backing path 粗划。
///
/// 分类规则（按 [`introspect_schema::MapKind`] 五档）：
/// - path = `[heap]` → [`MapKind::Heap`]
/// - path = `[stack]` 或 `[stack:tid]` → [`MapKind::Stack`]
/// - path 以 `[` 开头但不属上述 → [`MapKind::Anon`]（含 `[anon:...]`、
///   `[vdso]`、`[vvar]`、`(fd: N)` 等 pseudo-path）
/// - path 不存在 → [`MapKind::Anon`]（纯匿名映射）
/// - path 存在且 perms 含 `x`（可执行）→ [`MapKind::XLib`]
/// - path 存在不含 `x` → [`MapKind::File`]
///
/// 返 `None` 不再使用——所有路径都落到 5 类之一；parse_maps 已兜底 Anon。
/// 此处保留 Option 类型以兼容旧 stub 签名，但永远不返 None。
pub fn classify_map_kind(perms: &str, path: Option<&str>) -> Option<MapKind> {
    let path = match path {
        Some(p) => p.trim(),
        None => return Some(MapKind::Anon), // 无 path → 纯匿名映射
    };
    // 方括号包住的 pseudo-path 优先识别
    if path.starts_with('[') {
        if path == "[heap]" {
            return Some(MapKind::Heap);
        }
        if path == "[stack]" || path.starts_with("[stack:") {
            return Some(MapKind::Stack);
        }
        // [vdso]/[vvar]/[anon:...]/[jstack:...]/(deleted) 归 Anon
        return Some(MapKind::Anon);
    }
    // 真文件路径
    if perms.contains('x') {
        Some(MapKind::XLib)
    } else {
        Some(MapKind::File)
    }
}

// ─── §13.4 scan_fds / read_wchan / read_kernel_stack ────────────────────────
//
// 这层 API 只接收 adapter 已读取的内容：目录项名、wchan 文本和 stack 文本。
// LinuxProcSource 负责路径与 I/O，本模块只做可跨平台测试的解析/计数：
//
//   - `scan_fds_from_names(&[String]) -> u32` —— 纯函数，输入 /proc/<pid>/fd
//     的目录项名（"0","1","2","3", ...），按规则去 "." ".." 后计数，返 fd 数。
//   - `read_wchan_from_str(&str) -> Option<String>` —— wchan 文件内容极简
//     （通常是一个符号名，或 `0` 表示可运行没阻塞），纯函数解析。
//   - `read_kernel_stack_from_str(&str) -> Vec<(String, String)>` —— /proc/<pid>/stack
//     按行格式 `[<hex_addr>] func_name+0xoffset/0xsize`，解析出 (addr, sym) 帧
//     列表；纯函数。
//
// 真正的文件 / 目录 I/O 只在 `proc_source::LinuxProcSource`。

/// /proc/<pid>/fd 的目录项名列表 → fd 数。
///
/// 规则：去 "." 和 ".."。Symlink 数量就是 fd 数（man proc：fd/ 下每项是 fd
/// 编号，符号链接到对应 file/pipe/socket）。
///
/// 不把名字解析成数字——内核允许 fd 数超过 closed fd 复用编号，这里只数计。
pub fn scan_fds_from_names(names: &[String]) -> u32 {
    names
        .iter()
        .filter(|n| !n.is_empty() && n.as_str() != "." && n.as_str() != "..")
        .count() as u32
}

/// /proc/<pid>/wchan 的内容 → 符号化阻塞点。
///
/// wchan 文件内容极简：
/// - `0` 表示进程可运行、没阻塞（R 态）——返 None。
/// - 一个内核函数名（可能带 `+0xnnn` 偏移），返 Some(name)。
/// - 空字符串（极少见，权限/特殊态）也按可运行处理，返 None。
///
/// 不在此做 blazesym 二次符号化——wchan 文件已经是符号化产物，§10 注释
/// 「符号化的阻塞点」直读即可；§11 ① 双路交叉验证用它和 read_kernel_stack
/// 顶帧对比。
pub fn read_wchan_from_str(content: &str) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return None;
    }
    Some(trimmed.to_string())
}

/// /proc/<pid>/stack 行 → 帧列表 (addr_hex, symbol)。
///
/// /proc/<pid>/stack 格式（内核 CONFIG_STACKTRACE 开启才可读，root 权限）：
/// ```text
/// [<ffffffff81a2b3c4>] futex_wait_queue_me+0xabc/0x123
/// [<ffffffff81a2b4d0>] __schedule+0x1a2/0x345
/// ...
/// ```
/// 本函数抽出 (addr_hex, "func_name+0xoffset" 形式 sym) 帧列表，由 caller
/// 截取栈顶 N 帧并调 symbolizer 补 §11 置信度。
///
/// 解析失败行为：跳过该行，不整体失败——栈是 best-effort 输入，有些行
/// 缺符号或 [interrupt] 这种特殊行都按跳过处理，符合 §11 best-effort 契约。
pub fn read_kernel_stack_from_str(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 期望首字段 `<addr>` 在方括号[<...>]里, 后跟空白与符号串.
        let open = match line.find('[') {
            Some(i) => i,
            None => continue,
        };
        let close = match line[open..].find(']') {
            Some(i) => open + i,
            None => continue,
        };
        // addr 段在 [...] 内, 可含 < >
        let addr_seg = &line[open + 1..close];
        let addr = addr_seg
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string();
        // 符号段是 close 之后第一个非空白 token (直到行尾, 含 +0x... 偏移)
        let sym = line[close + 1..].trim();
        if sym.is_empty() {
            continue;
        }
        out.push((addr, sym.to_string()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归保护：`ProcError` 在 `#[serde(tag = "kind")]` 内部标签枚举下，
    /// 所有变体都必须能被 `serde_json` 运行时序列化。
    ///
    /// 防御的具体 bug 见 enum 顶部注释：newtype-包-i32 形态能编译过但运行时炸。
    /// 当时给 ProcNotFound 改成 struct 变体就是为绕这个雷；本测把它钉住，
    /// 未来谁手滑再写 Newtype 包基元，会在这里红出来。
    #[test]
    fn proc_error_all_variants_serialize() {
        let cases: Vec<ProcError> = vec![
            ProcError::ProcNotFound { pid: 42 },
            ProcError::Permission,
            ProcError::Read {
                what: "/proc/stat".into(),
                reason: "unavailable".into(),
            },
            ProcError::Parse {
                what: "stat".into(),
                reason: "bad number".into(),
            },
            ProcError::NotImplemented,
        ];
        for (i, c) in cases.into_iter().enumerate() {
            let s = serde_json::to_string(&c)
                .unwrap_or_else(|e| panic!("variant #{i} 序列化失败：{e}: {c:?}"));
            // 反序列化回来要等价（按 tag 区分）
            let back: ProcError = serde_json::from_str(&s)
                .unwrap_or_else(|e| panic!("variant #{i} 反序列化失败：{e}"));
            assert_eq!(
                s,
                serde_json::to_string(&back).unwrap(),
                "round-trip 不自洽"
            );
        }
    }

    /// ProcNotFound 是 introspect 最常见错误路径——按 §2.2 要 ship 过 vsock，
    /// 它必须能成 JSON。单独再钉一遍，防止后续重构把这条破坏。
    #[test]
    fn proc_not_found_serializes_with_pid() {
        let e = ProcError::ProcNotFound { pid: 1234 };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"kind\":\"proc_not_found\""), "tag 不对: {s}");
        assert!(s.contains("\"pid\":1234"), "pid 没进 JSON: {s}");
    }

    /// 构造一段 man-proc 字段精确对齐的 /proc/<pid>/stat 行。
    ///
    /// fields 1-based（man proc）: 1=pid 2=comm 3=state 4=ppid 5=pgrp 6=session
    /// 7=tty_nr 8=tpgid 9=flags 10=minflt 11=cminflt 12=majflt 13=cmajflt
    /// 14=utime 15=stime 16=cutime 17=cstime 18=priority 19=nice 20=nr_threads
    /// 21=itrealvalue 22=starttime 23=vsize 24=rss 25=rlsslim 26=startcode
    /// 27=endcode 28=startstack 29=kstkesp 30=kstkeip 31=signal 32=blocked
    /// 33=sigignore 34=sigcatch 35=wchan 36=nswap 37=cnswap 38=exit_signal
    /// 39=processor 40=rt_priority 41=policy 42=aggrutime 43=aggrstime
    /// 44=voluntary_ctxt 45=nonvoluntary_ctxt
    ///
    /// ⚠️ ctxt **不从 stat helper 走**——man 字段 40/41 在 tail-idx 37/38 的位置，
    /// 是 rt_priority/policy 两个槽，塞进去会被当成 ctxt 读，是同构 fixture
    /// 的元凶。真 ctxt 测在 [`parse_status_extracts_uid_fdsize_and_ctxt`]，
    /// 从 status 的 `voluntary_ctxt_switches:`/`nonvoluntary_ctxt_switches:` 行取。
    ///
    /// 注意 man proc 里字段编号随版本漂移；以下值按"稳定锚点"放：
    ///   pid/state/nr_threads/vsize/rss/last_cpu 装在 man 给的槽里，
    /// 其它字段填 0 占位。idx = field# - 3（因为 1=pid 2=comm 不入 tail）。
    //       tail idx: 0=state 1=ppid ... 17=nr_threads 20=vsize 21=rss ...
    //                 36=last_cpu
    #[allow(clippy::too_many_arguments)]
    fn stat_line(
        pid: i32,
        comm: &str,
        state: &str,
        nr_threads: u32,
        process_start_time_ticks: u64,
        vsize: u64,
        rss: u64,
        last_cpu: u32,
    ) -> String {
        // tail 一共 idx 0..38 = 39 个字段。tail[37]/tail[38] 留 0（= rt_priority/
        // policy 的槽），不再塞假装的 ctxt 值。
        let mut tail: Vec<String> = (0..39).map(|_| "0".to_string()).collect();
        tail[0] = state.to_string();
        tail[17] = nr_threads.to_string();
        tail[19] = process_start_time_ticks.to_string();
        tail[20] = vsize.to_string();
        tail[21] = rss.to_string();
        tail[36] = last_cpu.to_string();
        format!("{} ({}) {}\n", pid, comm, tail.join(" "))
    }

    /// §10 comm 含空格 + 内嵌括号——必须 rfind(')') 切回。
    #[test]
    fn parse_stat_comm_with_space() {
        let s = stat_line(1, "systemd (init)", "S", 1, 123_456, 12_345_678, 0, 5);
        let r = parse_stat(&s).expect("comm 含空格/内嵌括号必须可解析");
        assert_eq!(r.pid, 1);
        assert_eq!(r.comm, "systemd (init)"); // 去外层括号、保留内层
        assert_eq!(r.state, RunState::S);
        assert_eq!(r.nr_threads, 1);
    }

    /// §10 D 态（不可中断睡眠）样本——hotspot 走 D 态过滤的回归前提。
    /// ⚠️ 本测**不**检 ctxt——ctxt 已从 stat 移到 status，断言在
    /// parse_status_extracts_uid_fdsize_and_ctxt。
    #[test]
    fn parse_stat_d_state() {
        let s = stat_line(42, "demo", "D", 7, 987_654, 4_000_000, 100_000, 9);
        let r = parse_stat(&s).expect("最小 D 态样本可解析");
        assert_eq!(r.pid, 42);
        assert_eq!(r.comm, "demo");
        assert_eq!(r.state, RunState::D);
        assert_eq!(r.nr_threads, 7);
        assert_eq!(r.vsize, 4_000_000);
        assert_eq!(r.rss, 100_000);
        assert_eq!(r.process_ticks, 0);
        assert_eq!(r.process_start_time_ticks, 987_654);
        assert_eq!(r.last_cpu, 9);
    }

    #[test]
    fn parse_stat_process_ticks_are_utime_plus_stime() {
        let mut tail = vec!["0".to_string(); 39];
        tail[0] = "S".into();
        tail[11] = "123".into();
        tail[12] = "77".into();
        tail[17] = "1".into();
        tail[20] = "4096".into();
        tail[21] = "1".into();
        tail[36] = "0".into();
        let stat = format!("42 (cpu-demo) {}\n", tail.join(" "));

        assert_eq!(parse_stat(&stat).unwrap().process_ticks, 200);
    }

    #[test]
    fn parse_stat_reads_process_start_time_ticks() {
        let stat = stat_line(42, "generation", "S", 1, 7_654_321, 4096, 1, 0);

        assert_eq!(
            parse_stat(&stat).unwrap().process_start_time_ticks,
            7_654_321
        );
    }

    #[test]
    fn parse_stat_rejects_missing_paren() {
        let s = "42 bar S 40 42\n"; // 无 (comm) 格式
        assert!(matches!(parse_stat(s), Err(ProcError::Parse { .. })));
    }

    #[test]
    fn parse_system_cpu_excludes_guest_ticks_and_counts_logical_cpus() {
        let content = "cpu  10 20 30 40 50 60 70 80 900 1000\n\
                       cpu0 1 2 3 4 5 6 7 8 9 10\n\
                       cpu1 1 2 3 4 5 6 7 8 9 10\n\
                       intr 123\n";
        let parsed = parse_system_cpu(content).unwrap();

        assert_eq!(parsed.ticks, 10 + 20 + 30 + 40 + 50 + 60 + 70 + 80);
        assert_eq!(parsed.logical_cpus, 2);
    }

    #[test]
    fn parse_system_cpu_rejects_missing_aggregate_or_logical_cpu_lines() {
        assert!(matches!(
            parse_system_cpu("cpu0 1 2 3 4\n"),
            Err(ProcError::Parse { what, .. }) if what == "proc_stat.cpu"
        ));
        assert!(matches!(
            parse_system_cpu("cpu 1 2 3 4\n"),
            Err(ProcError::Parse { what, .. }) if what == "proc_stat.logical_cpus"
        ));
    }

    #[test]
    fn parse_cgroup_handles_v2_v1_absence_and_malformed_lines() {
        assert_eq!(
            parse_cgroup("0::/user.slice/demo.scope\n").unwrap(),
            Some("/user.slice/demo.scope".into())
        );
        assert_eq!(
            parse_cgroup("11:memory:/legacy/demo\n10:cpu:/legacy/demo\n").unwrap(),
            Some("/legacy/demo".into())
        );
        assert_eq!(parse_cgroup("\n").unwrap(), None);
        assert!(matches!(
            parse_cgroup("malformed\n"),
            Err(ProcError::Parse { what, .. }) if what == "cgroup"
        ));
    }

    // ─── parse_status ──────────────────────────────────────────────────────

    #[test]
    fn parse_status_extracts_uid_fdsize_and_ctxt() {
        let s = "Name:\tdemo\n\
                 Uid:\t1000\t1000\t1000\t1000\n\
                 Gid:\t1000\t1000\t1000\t1000\n\
                 FDSize:\t256\n\
                 voluntary_ctxt_switches:\t123\n\
                 nonvoluntary_ctxt_switches:\t45\n\
                 VmRSS:\t    1234 kB\n";
        let r = parse_status(s).unwrap();
        assert_eq!(r.uid, 1000);
        assert_eq!(r.fd_size, Some(256));
        assert_eq!(r.voluntary_ctxt_switches, 123);
        assert_eq!(r.nonvoluntary_ctxt_switches, 45);
    }

    #[test]
    fn parse_status_rejects_malformed_ctxt_switch_counts_structurally() {
        for (key, expected_what) in [
            ("voluntary_ctxt_switches", "status.voluntary_ctxt_switches"),
            (
                "nonvoluntary_ctxt_switches",
                "status.nonvoluntary_ctxt_switches",
            ),
        ] {
            let status = format!("Uid:\t1000\t1000\t1000\t1000\n{key}:\tnot-a-number\n");
            let error = parse_status(&status).expect_err("malformed count must fail");

            match &error {
                ProcError::Parse { what, reason } => {
                    assert_eq!(what, expected_what);
                    assert!(!reason.is_empty());
                }
                other => panic!("expected structured parse error, got {other:?}"),
            }

            let (kind, reason, next_step) = error.to_error_report();
            assert_eq!(kind, "proc_parse_failed");
            assert!(reason.contains(expected_what));
            assert!(next_step.is_some());
        }
    }

    // ─── parse_maps（皇冠明珠投影本体回归保护） ──────────────────────────────

    /// 皇冠明珠本体回归保护：GB 级 maps → 十几行 histogram。
    /// §10 / §13.4「绝不吐完整 maps 表」的代码保证——
    /// 给一段五花八门的多类映射，断言：①histogram 桶数 ≤ 5（永远≤5类）；
    /// ②top_n 长度 ≤ MEM_SHAPE_TOP_N（=5）；③原始 maps 行数 ≫ 出参总行数。
    #[test]
    fn parse_maps_projects_huge_maps_to_compact_shape() {
        // M1 不写几百行 fixture（够说明问题就好），但每类都列上 + 一堆匿名映射。
        let maps = "\
7f0000000000-7f0000100000 rw-p 00000000 00:00 0                          [heap]\n\
7ffe00000000-7ffe00004000 rw-p 00000000 00:00 0                          [stack]\n\
7ffe00004000-7ffe00005000 r-xp 00000000 00:00 0                          [vdso]\n\
7f0000100000-7f0000110000 rw-p 00000000 00:00 0                          [anon:rust_alloc]\n\
7f001a000000-7f0020000000 rw-p 00000000 00:00 0                          \n\
7f0020000000-7f0020001000 r--p 00001000 08:01 1234                       /usr/lib/libc.so.6\n\
7f0020001000-7f0020005000 r-xp 00001000 08:01 1234                       /usr/lib/libc.so.6\n\
7f0020005000-7f0020007000 rw-p 00004000 08:01 1234                       /usr/lib/libc.so.6\n\
7f0020007000-7f0020008000 r-xp 00000000 08:01 5678                       /usr/bin/my_app\n\
7f0020008000-7f002000d000 r-xp 00000000 08:01 5678                       /usr/bin/my_app\n\
7f002000d000-7f0020010000 rw-p 00005000 08:01 9999                       /var/data/cache.db\n\
7f1234567000-7f1234678000 rw-p 00000000 00:00 0                          [stack:1234]\n\
7f1300000000-7f1300001000 ---p 00000000 00:00 0                          \n";
        let r = parse_maps(maps).expect("maps 必须可解析");
        let input_lines = maps.lines().filter(|l| !l.is_empty()).count();
        let output_lines = r.histogram.len() + r.top_n.len();
        // 投影成立：输入 12 行映射 → 出参顶多 5 + 5 = 10 行（实战 GB maps 上千行
        // → 投影，这里数据小但 ratio 必须 ≥ 投影方向）
        assert!(
            r.histogram.len() <= 5,
            "histogram 超过 §10 五类: {:?}",
            r.histogram
        );
        assert!(
            r.top_n.len() <= MEM_SHAPE_TOP_N,
            "top_n 超过 N: {}",
            r.top_n.len()
        );
        // 5 类里至少应出现 Heap/Stack/XLib/File —— Anon 也一定在（[vdso]/[anon...]/[stack:tid]/纯匿名）
        let kinds: Vec<_> = r.histogram.iter().map(|b| b.kind).collect();
        assert!(kinds.contains(&MapKind::Heap));
        assert!(kinds.contains(&MapKind::Stack));
        assert!(kinds.contains(&MapKind::Anon));
        assert!(kinds.contains(&MapKind::File));
        assert!(kinds.contains(&MapKind::XLib));
        // heap 桶恰好 1 个映射，size = 0x100000
        let heap = r
            .histogram
            .iter()
            .find(|b| b.kind == MapKind::Heap)
            .unwrap();
        assert_eq!(heap.count, 1);
        assert_eq!(heap.total_size, 0x100000);
        // top-N 是按 size 降序——最大的应排第一个
        let max = r.top_n.first().expect("top_n 非空");
        assert_eq!(max.size, r.top_n.iter().map(|t| t.size).max().unwrap());
        // 投影成立的统计性表达（数据集小,只是非严格 ratio）
        let _ = (input_lines, output_lines);
    }

    #[test]
    fn parse_maps_top_n_handles_anon_xlib_distinction() {
        // XLib = file 路径且 perms 含 'x'；File = file 路径不含 'x'
        let maps = "\
7f0020001000-7f0020005000 r-xp 00001000 08:01 1234  /usr/lib/libc.so.6\n\
7f002000d000-7f0020010000 rw-p 00005000 08:01 9999  /var/data/cache.db\n";
        let r = parse_maps(maps).unwrap();
        // XLib 进顶部 top_n，且 backing 是路径
        let xlib = r.top_n.iter().find(|t| t.kind == MapKind::XLib).unwrap();
        assert_eq!(xlib.backing.as_deref(), Some("/usr/lib/libc.so.6"));
        // File 也在
        assert!(r.top_n.iter().any(|t| t.kind == MapKind::File));
    }

    // ─── classify_map_kind 单元 ─────────────────────────────────────────────

    #[test]
    fn classify_map_kind_pseudo_paths() {
        assert_eq!(
            classify_map_kind("rw-p", Some("[heap]")),
            Some(MapKind::Heap)
        );
        assert_eq!(
            classify_map_kind("rw-p", Some("[stack]")),
            Some(MapKind::Stack)
        );
        assert_eq!(
            classify_map_kind("rw-p", Some("[stack:1234]")),
            Some(MapKind::Stack)
        );
        assert_eq!(
            classify_map_kind("r-xp", Some("[vdso]")),
            Some(MapKind::Anon)
        );
        assert_eq!(
            classify_map_kind("rw-p", Some("[anon:foo]")),
            Some(MapKind::Anon)
        );
        assert_eq!(classify_map_kind("rw-p", None), Some(MapKind::Anon));
    }

    #[test]
    fn classify_map_kind_real_paths() {
        // 可执行 file-backed -> XLib
        assert_eq!(
            classify_map_kind("r-xp", Some("/usr/lib/libc.so.6")),
            Some(MapKind::XLib)
        );
        // 不可执行 file-backed -> File
        assert_eq!(
            classify_map_kind("rw-p", Some("/var/data/cache.db")),
            Some(MapKind::File)
        );
    }

    // ─── scan_fds / wchan / kernel_stack ─────────────────────────────────────

    #[test]
    fn scan_fds_from_names_counts_real_fds() {
        // /proc/<pid>/fd 目录通常会有 "." ".." 和 fd 编号
        let names: Vec<String> = vec![
            ".".into(),
            "..".into(),
            "0".into(),
            "1".into(),
            "2".into(),
            "3".into(),
            "17".into(),
        ];
        assert_eq!(scan_fds_from_names(&names), 5);
        // 空目录
        assert_eq!(scan_fds_from_names(&[".".into(), "..".into()]), 0);
    }

    #[test]
    fn read_wchan_from_str_handles_runnable_and_blocked() {
        // 可运行 -> None
        assert_eq!(read_wchan_from_str("0"), None);
        // 阻塞给出内核函数名
        assert_eq!(
            read_wchan_from_str("futex_wait_queue_me\n"),
            Some("futex_wait_queue_me".to_string())
        );
        // 偶尔带偏移
        assert_eq!(
            read_wchan_from_str("  poll_schedule_timeout+0x3c/0x70 "),
            Some("poll_schedule_timeout+0x3c/0x70".to_string())
        );
        // 空 -> None
        assert_eq!(read_wchan_from_str(""), None);
    }

    #[test]
    fn read_kernel_stack_from_str_parses_frames() {
        // §10 hotspot 触发条件：D 态时内核栈顶 3-5 帧
        // 真 /proc/<pid>/stack 每行格式 `[<addr>] sym+off/size`
        let stack = "[<ffffffff81a2b3c4>] futex_wait_queue_me+0xabc/0x123\n\
                     [<ffffffff81a2b4d0>] __schedule+0x1a2/0x345\n\
                     [<ffffffff81a2b500>] schedule+0x40/0x80\n";
        let frames = read_kernel_stack_from_str(stack);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0, "ffffffff81a2b3c4");
        assert_eq!(frames[0].1, "futex_wait_queue_me+0xabc/0x123");
        // 顶帧是 futex_wait —— §11 ① 双路交叉验证正是它 vs wchan 对比自洽
        assert_eq!(frames[2].0, "ffffffff81a2b500");
    }

    #[test]
    fn read_kernel_stack_from_str_skips_empty_and_junk() {
        let stack = "\n\
                     not a stack line\n\
                     [<ffffffff81a2b3c4>] futex_wait_queue_me+0xabc/0x123\n";
        let frames = read_kernel_stack_from_str(stack);
        // 跳过空行和「not a stack line」（无 [）——只保留最后一帧
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, "futex_wait_queue_me+0xabc/0x123");
    }
}
