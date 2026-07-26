//! `introspect(pid)` 引擎（§10）。
//!
//! M1 第二刀：[`engine::introspect`] 从 stub `NotImplemented`
//! 转为返真 [`introspect_schema::Level0`]。按 §13.4 的六步流程：
//!   1. 调 [`crate::proc_view`] 的 6 个纯解析函数拿到字段件件；
//!   2. 构造 MemShape / ProcState / Identity / Resource；
//!   3. Hotspot 仅 D 态触发——读 /proc/<pid>/stack 顶 3-5 帧并 dereference
//!      到 [`crate::symbolize::Symbolizer`] 拿 per-frame 置信度；
//!   4. `recent` 恒返 [`introspect_schema::RecentEvents::RecorderOff`]（M4 在位
//!      之前一律如此，§10 明写）；
//!   5. confidence：调 [`crate::symbolize::Symbolizer::cross_check`] 验 wchan
//!      vs 顶帧自洽（§11 ①）；不自洽推 `low_fields`；
//!   6. handles 一律 None（M3 才给可消费 cursor）；cost_hint 算 token 估算
//!      + overhead_est_ns = 0（零探针承诺的代码体现）。
//!
//! 注意本刀的边界：**真 /proc I/O 那一层**（`fs::read_to_string("/proc/<pid>/stat")`
//! 这类薄壳函数）尚未落地——M0 进靶机时一次性补 cfg-gate 到 Linux。
//! 本刀 engine 调用形态就位，谁先用 cross-cutting 测就拍 fixture string 走过
//! `proc_view` 的纯函数层，让 engine 透传到 Level0 的形态准确。
//!
//! 设计上 `engine::introspect` 的**对外签名保持不变**——返 `Result<Level0, ProcError>`。
//! 跨 vsock 时由调用方把 `ProcError::to_error_report` 三元组包成 `ErrorReport`。

use introspect_schema::{
    ConfidenceSummary, CostHint, Handles, Hotspot, Identity, Level0, LowConfidenceField,
    ProcState, RecentEvents, Resource, RunState, StackFrame, SymbolConfidence,
    Symbolized,
};

use crate::proc_view::{self, ProcError, CMDLINE_SHORT_MAX, MEM_SHAPE_TOP_N};
use crate::symbolize::{FallbackSymbolizer, Symbolizer};

/// §10 `introspect(pid) -> Level0` 的对外入口。
///
/// M1 第二刀实现：真 stmt 在 [Self::build_level0] 里，签名保持为
/// `Result<Level0, ProcError>` 不变。
pub fn introspect(pid: i32) -> Result<Level0, ProcError> {
    // 零探针承诺的具现：用 FallbackSymbolizer 时不会触任何 blazesym / 内核 lookup。
    // M0 进靶机后这里换成 blaze::BlazeSymbolizer::new_kernel()。
    let sym: Box<dyn Symbolizer> = Box::new(FallbackSymbolizer);
    introspect_with(pid, sym.as_ref())
}

/// 内层入口：注入一个 [`Symbolizer`] 跑样例。让单测能在 Mac 上跑通形态，
/// 不需要真 blazesym 后端。
pub fn introspect_with(pid: i32, sym: &dyn Symbolizer) -> Result<Level0, ProcError> {
    // §13.4 六步的 step 1：proc_view 全套字段件件件。
    // 但真 /proc I/O 那半 cfg-gate 到 Linux 才有；非 Linux（含 Mac）跑 engine
    // 等于在没文件的情况下做组装——直接返 NotImplemented，等 M0 进靶机后才能
    // 跑端到端。本刀的形态对齐由 introspect_with_with_inputs 单测盯住。
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, sym);
        return Err(ProcError::NotImplemented);
    }
    #[cfg(target_os = "linux")]
    {
        introspect_linux(pid, sym)
    }
}

#[cfg(target_os = "linux")]
fn introspect_linux(pid: i32, sym: &dyn Symbolizer) -> Result<Level0, ProcError> {
    use std::fs;

    let stat_s = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| map_io_err(e, pid))?;
    let status_s = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| map_io_err(e, pid))?;
    let maps_s = fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| map_io_err(e, pid))?;
    let wchan_s = fs::read_to_string(format!("/proc/{pid}/wchan"))
        .ok()
        .unwrap_or_default();
    let cmdline_s = fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|e| map_io_err(e, pid))?;

    // /proc/<pid>/fd 扫描
    let fd_names: Vec<String> = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|e| map_io_err(e, pid))?
        .filter_map(|e| e.ok())
        .filter_map(|d| d.file_name().into_string().ok())
        .collect();

    // D 态触发：只有 D 状态下读 /proc/<pid>/stack 才有意义
    let stack_s = fs::read_to_string(format!("/proc/{pid}/stack")).ok().unwrap_or_default();

    introspect_with_inputs(
        pid, &stat_s, &status_s, &maps_s, &wchan_s, &cmdline_s, &fd_names, &stack_s, sym,
    )
}

/// 把解析的字符串件件组装成 [`Level0`]。**纯函数**——给单测盯住 §10 Level0
/// 的形态对齐。
///
/// Mac 上单测通过把 fixture string 喂进这里跑通引擎形态——这是 "真 /proc I/O
/// 那半 cfg-gate 到 Linux，但 Level0 组件形态可在 Mac 单测" 这一刀的体现。
#[allow(clippy::too_many_arguments)]
pub fn introspect_with_inputs(
    pid: i32,
    stat_s: &str,
    status_s: &str,
    maps_s: &str,
    wchan_s: &str,
    cmdline_bytes: &[u8],
    fd_names: &[String],
    stack_s: &str,
    sym: &dyn Symbolizer,
) -> Result<Level0, ProcError> {
    let stat = proc_view::parse_stat(stat_s)?;
    let status = proc_view::parse_status(status_s)?;
    let mem_shape = proc_view::parse_maps(maps_s)?;
    let nr_fds = proc_view::scan_fds_from_names(fd_names);
    let wchan_raw = proc_view::read_wchan_from_str(wchan_s);
    let kernel_stack = proc_view::read_kernel_stack_from_str(stack_s);

    // ─── identity ─────────────────────────────────────────────────
    // §10: identity = pid/comm/exe/cmdline(截断)/uid/cgroup
    // exe/cgroup 是 follow symlink / read file 那半——M0 cfg-gate 落真。本刀不在。
    let cmdline = build_cmdline(cmdline_bytes);
    let identity = Identity {
        pid,
        comm: stat.comm.clone(),
        exe: None,           // TODO(M0)：readlink /proc/<pid>/exe
        cmdline,
        uid: status.uid,
        cgroup: None,        // TODO(M0)：read /proc/<pid>/cgroup 第一行
    };

    // ─── state (含 wchan + §11 ① 双路交叉验证) ─────────────────────
    let wchan = match &wchan_raw {
        Some(name) => {
            // wchan 文件内容已经是符号化的——但 §11 ① 要求和 /proc/<pid>/stack 顶帧
            // 比对自洽。若不自洽，下游 confidence 要降权；这里先存进 §11 置信度表示。
            // M1 用 Kallsyms 那档——内核给的 wchan 至少 kallsyms 命中。
            Some(Symbolized {
                name: name.clone(),
                source: SymbolConfidence::Kallsyms,
            })
        }
        None => None,
    };
    let run_state = stat.state;
    let state = ProcState {
        run_state,
        last_cpu: stat.last_cpu,
        nr_threads: stat.nr_threads,
        wchan: wchan.clone(),
    };

    // ─── resource（含 %cpu 短采样, 本刀 zero，TODO(M1.5) 真实现）──────────
    // stat.rss 是**页数**——x86_64/aarch64 默认 page = 4096；M0 需拿 sysconf。
    // M1 第二刀暂按 4096 死乘到字节, 不再读 getconf（Mac 上没 SC_PAGESIZE 同名宏
    // 但本路径 cfg-gate 到 Linux，没这事在 Mac 跑；本刀估 4KiB 是常规页）
    let rss_bytes = stat.rss.saturating_mul(4096);
    let resource = Resource {
        rss_bytes,
        vsz_bytes: stat.vsize,
        nr_fds,
        // %cpu 短采样还没落地——M1 第二刀保守给 0.0，TODO 标 M1.5。
        pct_cpu: 0.0,
        ctxt_switches: introspect_schema::CtxtSwitches {
            voluntary: status.voluntary_ctxt_switches,
            nonvoluntary: status.nonvoluntary_ctxt_switches,
        },
    };

    // ─── hotspot（§10：D 态时给内核栈顶 3-5 帧 + per-frame 置信度）─────
    let hotspot = build_hotspot(run_state, &kernel_stack, sym);

    // ─── recent (§10 常驻飞行记录仪未在跑) ────────────────────────
    let recent = RecentEvents::RecorderOff;

    // ─── confidence (§11 ① 双路交叉验证) ──────────────────────────
    // §11 ① 双路交叉验证：wchan 符号化结果 vs /proc/<pid>/stack 顶帧是否自洽。
    // completed hotspot 同时提供逐帧符号置信度和交叉校验所需的顶帧。
    let confidence = build_confidence(&wchan_raw, &hotspot, sym);

    // ─── handles (§10 全 None, M3 才给可消费 cursor) ──────────────
    let handles = Handles::default();

    // ─── cost_hint（§10 钉死：每次带 cost_hint; §12 形状已定）──────
    // overhead_est_ns = 0 是零探针承诺的代码体现。
    // token 估：粗估——Level0 JSON 大概 500-2000 token 当下规模；M1 给 500 作 floor。
    let cost_hint = CostHint {
        token: 500,
        api_cost: None,
        overhead_est_ns: 0,
    };

    Ok(Level0 {
        identity,
        state,
        resource,
        mem_shape,
        hotspot,
        recent,
        confidence,
        handles,
        cost_hint,
    })
}

/// 把 /proc/<pid>/cmdline 的 \0 分隔字节拼成 [`Cmdline`]。
fn build_cmdline(bytes: &[u8]) -> introspect_schema::Cmdline {
    // /proc/<pid>/cmdline 用 \0 分隔多个 argv 元素。
    // 本刀简化：把 \0 替换成空格, 然后按 Unicode scalar 截到 CMDLINE_SHORT_MAX。
    let joined = String::from_utf8_lossy(bytes)
        .replace('\u{0}', " ")
        .trim()
        .to_string();
    let full_len = joined.len();
    let mut chars = joined.chars();
    let mut short: String = chars.by_ref().take(CMDLINE_SHORT_MAX).collect();
    if chars.next().is_some() {
        short.push('…');
    }
    introspect_schema::Cmdline {
        short,
        full_len,
    }
}

/// §10 hotspot 构造：非 D 态 NotBlocked；D 态时取栈顶 min(5, frames.len()) 帧。
fn build_hotspot(
    run_state: RunState,
    kernel_stack: &[(String, String)],
    sym: &dyn Symbolizer,
) -> Hotspot {
    if run_state != RunState::D || kernel_stack.is_empty() {
        return Hotspot::NotBlocked;
    }
    let take_n = MEM_SHAPE_TOP_N.min(kernel_stack.len());
    let mut frames = Vec::with_capacity(take_n);
    for (idx, (addr_s, _sym_raw)) in kernel_stack.iter().take(take_n).enumerate() {
        let addr = u64::from_str_radix(addr_s.trim_start_matches("0x"), 16).unwrap_or(0);
        // sym_raw 形如 "futex_wait_queue_me+0xabc/0x123"；§11 要求 per-frame 置信度。
        // 真 blazesym 后端（M0 Linux）会做符号化推断；FallbackSymbolizer 返 NotFound，
        // 我们应该诚实把帧标 None 置信度——不假装符号化成功。
        let (symbol, confidence) = match sym.symbolize(addr) {
            Ok(s) => {
                let conf = s.source;
                (Some(s), Some(conf))
            }
            Err(_) => (None, None),
        };
        frames.push(StackFrame {
            idx: idx as u32,
            addr: addr_s.clone(),
            symbol,
            confidence,
        });
    }
    Hotspot::Blocked { frames }
}

/// §11 confidence：双路交叉验证 + low_fields 聚合。
///
/// §11 ①：wchan 存在 + kernel stack 顶帧存在 → 调 `cross_check` 自洽比对；
/// 不自洽 → 把 `state.wchan` 加进 low_fields + `hotspot.frames[0].symbol` 加进 low_fields。
/// §11 ②：per-frame 符号化失败 → 进 low_fields。
/// §11 ③：置信度是一等输出——本函数是「它告诉你它有多不确定」的代码归宿。
fn build_confidence(
    wchan_raw: &Option<String>,
    hotspot: &Hotspot,
    sym: &dyn Symbolizer,
) -> ConfidenceSummary {
    let mut low_fields: Vec<LowConfidenceField> = Vec::new();
    let mut symbol_scores = Vec::new();

    if let Hotspot::Blocked { frames } = hotspot {
        for frame in frames {
            let confidence = match (&frame.symbol, frame.confidence) {
                (Some(_), Some(confidence)) => confidence,
                _ => SymbolConfidence::None,
            };
            symbol_scores.push(confidence.score());
            if confidence == SymbolConfidence::None {
                low_fields.push(LowConfidenceField {
                    path: format!("hotspot.frames[{}].symbol", frame.idx),
                    confidence: Some(SymbolConfidence::None),
                    reason: "blocked frame symbolization failed or produced no confidence".into(),
                });
            }
        }
    }

    // ① wchan vs 顶帧自洽性
    let mut cross_check_failed = false;
    let top_frame = match hotspot {
        Hotspot::Blocked { frames } => frames.first(),
        Hotspot::NotBlocked => None,
    };
    if let (Some(wchan_name), Some(top_frame)) = (wchan_raw, top_frame) {
        let top_addr =
            u64::from_str_radix(top_frame.addr.trim_start_matches("0x"), 16).unwrap_or(0);
        if let Some(reason) = sym.cross_check(top_addr, wchan_name) {
            cross_check_failed = true;
            low_fields.push(LowConfidenceField {
                path: "state.wchan".into(),
                confidence: Some(SymbolConfidence::Kallsyms),
                reason,
            });
            low_fields.push(LowConfidenceField {
                path: "hotspot.frames[0].symbol".into(),
                confidence: Some(SymbolConfidence::Kallsyms),
                reason: "wchan/顶帧不自洽：wchan 是可信嫌疑方之一".into(),
            });
        }
    }

    // ② 整体 overall：已观测帧的符号置信度算术平均；无符号观测时为 1.0。
    // wchan/顶帧交叉校验失败时，即使单帧符号本身很强，整体也不得高于 0.5。
    let mut overall = if symbol_scores.is_empty() {
        1.0
    } else {
        symbol_scores.iter().sum::<f32>() / symbol_scores.len() as f32
    };
    if cross_check_failed {
        overall = overall.min(0.5);
    }

    ConfidenceSummary {
        overall,
        low_fields,
    }
}

/// /proc I/O 失败映射到 [`ProcError`]（cfg-gate Linux 才用，Mac 上不编）。
#[cfg(target_os = "linux")]
fn map_io_err(e: std::io::Error, pid: i32) -> ProcError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => ProcError::ProcNotFound { pid },
        ErrorKind::PermissionDenied => ProcError::Permission,
        _ => ProcError::Parse {
            what: "io".into(),
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolize::{make_symbolized, SymbolizeError};
    use introspect_schema::MapKind;

    /// 引擎在 Mac 上跑 introspect() —— cfg-gate 直接走 NotImplemented，
    /// 不真读 /proc。不返 panic / io 错——这是 cfg gate 健全性回归。
    #[test]
    fn nonsense_on_non_linux() {
        let r = introspect(1);
        match r {
            Err(ProcError::NotImplemented) => {}
            Ok(_) => panic!("Mac 上不该构造 Level0（cfg-gate 跑的是 introspect_with_inputs）"),
            Err(other) => panic!("非 Linux 上预期 NotImplemented; 实际 {other:?}"),
        }
    }

    /// 引擎形态对齐：给一组 fixture 字符串通过 introspect_with_inputs 让
    /// Level0 全字段组装成立。M1 第二刀的端到端单测占位——真 /proc 集成测
    /// 在 M0 才跑（cfg-gate Linux）。
    #[test]
    fn introspect_with_inputs_builds_level0() {
        // 真 /proc/<pid>/stat 是一行。idx 严格按 man proc（state=0/nr_threads=17/
        // vsize=20/rss=21/last_cpu=36）；37/38 是 rt_priority/policy，不是 ctxt。
        let mut stat_fields = vec!["0"; 39];
        stat_fields[0] = "D";
        stat_fields[17] = "7";
        stat_fields[20] = "4000000";
        stat_fields[21] = "100000";
        stat_fields[36] = "9";
        stat_fields[37] = "900";
        stat_fields[38] = "901";
        let stat = format!("42 (demo) {}\n", stat_fields.join(" "));
        let status = "Name:\tdemo\n\
                      Uid:\t1000\t1000\t1000\t1000\n\
                      FDSize:\t64\n\
                      voluntary_ctxt_switches:\t3\n\
                      nonvoluntary_ctxt_switches:\t17\n";
        let maps = "\
7f0000000000-7f0000100000 rw-p 00000000 00:00 0                          [heap]\n\
7ffe00000000-7ffe00004000 rw-p 00000000 00:00 0                          [stack]\n\
7f0020001000-7f0020005000 r-xp 00001000 08:01 1234  /usr/lib/libc.so.6\n\
7f002000d000-7f0020010000 rw-p 00005000 08:01 9999  /var/data/cache.db\n";
        let wchan = "futex_wait_queue_me\n";
        let cmdline: &[u8] = b"./demo\0--foo\0--bar\0";
        let fds: Vec<String> = vec![".".into(), "..".into(), "0".into(), "1".into(), "2".into()];
        let stack = "[<ffffffff81a2b3c4>] futex_wait_queue_me+0xabc/0x123\n\
                     [<ffffffff81a2b4d0>] __schedule+0x1a2/0x345\n";

        let sym = FallbackSymbolizer;
        let l0 = introspect_with_inputs(
            42, &stat, status, maps, wchan, cmdline, &fds, stack, &sym,
        ).expect("纯函数形态必须可组装 Level0");

        // identity
        assert_eq!(l0.identity.pid, 42);
        assert_eq!(l0.identity.comm, "demo");
        assert_eq!(l0.identity.uid, 1000);
        assert_eq!(l0.identity.cmdline.full_len, 18); // "./demo\0--foo\0--bar\0" = 18 字节
        assert!(l0.identity.cmdline.short.contains("./demo"));

        // state
        assert_eq!(l0.state.run_state, RunState::D);
        assert_eq!(l0.state.nr_threads, 7);
        assert_eq!(l0.state.last_cpu, 9);
        assert!(l0.state.wchan.is_some());
        assert!(l0.state.wchan.as_ref().unwrap().name.contains("futex_wait"));

        // resource
        assert_eq!(l0.resource.rss_bytes, 100_000 * 4096);
        assert_eq!(l0.resource.vsz_bytes, 4_000_000);
        assert_eq!(l0.resource.nr_fds, 3);
        assert_eq!(l0.resource.ctxt_switches.voluntary, 3);
        assert_eq!(l0.resource.ctxt_switches.nonvoluntary, 17);

        // mem_shape（皇冠明珠投影）
        assert!(l0.mem_shape.histogram.len() <= 5);
        assert!(l0.mem_shape.top_n.len() <= MEM_SHAPE_TOP_N);
        assert!(l0.mem_shape.histogram.iter().any(|b| b.kind == MapKind::Heap));
        assert!(l0.mem_shape.histogram.iter().any(|b| b.kind == MapKind::XLib));

        // hotspot（D 态有 kernel stack）
        let frames = match &l0.hotspot {
            Hotspot::Blocked { frames } => frames,
            other => panic!("D 态应有 hotspot; 实际 {other:?}"),
        };
        assert!(frames.len() <= MEM_SHAPE_TOP_N);
        assert!(frames.len() <= 5);

        // recent = RecorderOff（M4 前的承诺）
        assert!(matches!(l0.recent, RecentEvents::RecorderOff));

        // handles 全 None (Handles::default)
        assert!(l0.handles.threads.is_none());
        assert!(l0.handles.maps.is_none());

        // cost_hint 形状（§10 钉死: 每次返回带）
        assert_eq!(l0.cost_hint.token, 500);
        assert!(l0.cost_hint.api_cost.is_none());
        assert_eq!(l0.cost_hint.overhead_est_ns, 0);
    }

    #[test]
    fn cmdline_truncates_at_unicode_scalar_boundaries() {
        let at_255 = "a".repeat(255);
        let at_256 = "b".repeat(256);
        let at_257 = "c".repeat(257);

        assert_eq!(build_cmdline(at_255.as_bytes()).short, at_255);
        assert_eq!(build_cmdline(at_256.as_bytes()).short, at_256);

        let truncated = build_cmdline(at_257.as_bytes());
        assert_eq!(truncated.short.chars().count(), 257);
        assert!(truncated.short.ends_with('…'));
        assert_eq!(truncated.full_len, 257);
    }

    #[test]
    fn cmdline_multibyte_character_crossing_byte_256_stays_valid_utf8() {
        let joined = format!("{}éz", "a".repeat(255));
        let cmdline = build_cmdline(joined.as_bytes());

        assert_eq!(cmdline.full_len, 258);
        assert_eq!(cmdline.short.chars().count(), 257);
        assert!(cmdline.short.ends_with("é…"));
    }

    struct SuccessfulSymbolizer;

    impl Symbolizer for SuccessfulSymbolizer {
        fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            let confidence = if addr == 1 {
                SymbolConfidence::Dwarf
            } else {
                SymbolConfidence::Kallsyms
            };
            Ok(make_symbolized(format!("frame_{addr}"), confidence))
        }
    }

    #[test]
    fn confidence_averages_successful_frame_symbols() {
        let stack = vec![
            ("1".to_string(), "frame_1".to_string()),
            ("2".to_string(), "frame_2".to_string()),
        ];
        let sym = SuccessfulSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &sym);
        let confidence = build_confidence(&None, &hotspot, &sym);

        assert!((confidence.overall - 0.875).abs() < f32::EPSILON);
        assert!(confidence.low_fields.is_empty());
    }

    #[test]
    fn failed_blocked_frame_symbols_lower_overall_confidence() {
        let stack = vec![
            ("1".to_string(), "frame_1".to_string()),
            ("2".to_string(), "frame_2".to_string()),
        ];
        let sym = FallbackSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &sym);
        let confidence = build_confidence(&None, &hotspot, &sym);

        assert_eq!(confidence.overall, 0.0);
        assert_eq!(confidence.low_fields.len(), 2);
        for (idx, field) in confidence.low_fields.iter().enumerate() {
            assert_eq!(field.path, format!("hotspot.frames[{idx}].symbol"));
            assert_eq!(field.confidence, Some(SymbolConfidence::None));
        }
    }

    struct CrossCheckFailureSymbolizer;

    impl Symbolizer for CrossCheckFailureSymbolizer {
        fn symbolize(&self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
            Ok(make_symbolized("frame", SymbolConfidence::Dwarf))
        }

        fn cross_check(&self, _addr: u64, _expected_top_frame: &str) -> Option<String> {
            Some("wchan/top frame mismatch".into())
        }
    }

    #[test]
    fn failed_cross_check_caps_overall_confidence() {
        let stack = vec![("1".to_string(), "frame".to_string())];
        let sym = CrossCheckFailureSymbolizer;
        let hotspot = build_hotspot(RunState::D, &stack, &sym);
        let confidence = build_confidence(&Some("wchan".into()), &hotspot, &sym);

        assert_eq!(confidence.overall, 0.5);
        assert!(confidence
            .low_fields
            .iter()
            .any(|field| field.path == "state.wchan"));
    }

    /// ProcError::to_error_report 三元组形状——跨 vsock 兜底契约。
    #[test]
    fn proc_error_to_error_report_shape() {
        let e = ProcError::ProcNotFound { pid: 999 };
        let (kind, reason, next_step) = e.to_error_report();
        assert_eq!(kind, "proc_not_found");
        assert!(reason.contains("999"));
        assert!(next_step.is_some());
    }
}
