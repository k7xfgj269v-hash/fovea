//! 符号化 + 回溯（§4.2 / §13.1）。
//!
//! §13.1：「**这是最重要的库选择——符号化质量 = 内省质量**」，选 blazesym
//! (libbpf 组织出品；统一处理 ELF/DWARF/kallsyms/gsym + DWARF/ORC 回溯)。
//!
//! M1 第二刀接 blazesym 0.2.5 的 ELF 路径（features = `["dwarf", "demangle"]`）：
//!   - `BlazeSymbolizer`（`#[cfg(target_os = "linux")]`）包 blazesym Symbolizer，
//!     真正的内核符号化要 M0 进靶机后一次性配 vmlinux/kallsyms/BTF path 才落。
//!   - `blazesym::symbolize::Sym` 自己**没有** source 字段——要按 code_info/size
//!     是否存在推断 §11 五档置信度（见 `blaze_confidence`）。
//! 非 Linux（含 Mac）走 [`FallbackSymbolizer`]——它诚实返 `NotFound`，不假装
//! 符号化成功，下游看到 NotFound 就知道**不能信**这一帧（§11 None 那档）。
//!
//! §11 ① 双路交叉验证：wchan 符号化结果 vs `/proc/<pid>/stack` 顶帧自洽。
//! `Symbolizer::cross_check` 是这一招的代码归宿。

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
use introspect_schema::SymbolConfidence;
use introspect_schema::Symbolized;

/// 符号化失败模式。
#[derive(Debug, Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymbolizeError {
    #[error("地址 {addr} 超出已知符号范围")]
    NotFound { addr: String },
    #[error("符号文件不可获得")]
    NoSymbolFile,
    #[error("blazesym 后端调用失败：{reason}")]
    Backend { reason: String },
}

/// §4.2 符号化器抽象。两个实现：
///   - [`FallbackSymbolizer`]：非 Linux 的诚实最劣路径（不调 blazesym）
///   - [`BlazeSymbolizer`]（Linux cfg gate）：真 blazesym 路径
///
/// 单测可内插自己的 mock 实现跑通流程，不依赖任一真实后端。
pub trait Symbolizer: Send + Sync {
    /// 把一个内核态地址符号化。
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError>;

    /// §11 ① 双路交叉验证：拿地址 + 预期顶帧，比对自洽性。
    /// 返回 Some(reason) = 不自洽（要进 `ConfidenceSummary.low_fields`）。
    /// 默认 None 表示「没有交叉证据可判」——保持沉默不强加置信度，
    /// 是 §11 「研究机不追求绝对正确，追求它告诉你它有多不确定」的体现。
    fn cross_check(&self, _addr: u64, _expected_top_frame: &str) -> Option<String> {
        None
    }
}

/// 一个永远返 [`SymbolizeError::NotFound`] 的最朴素 fallback；不调 blazesym。
///
/// 这**不是**「kallsyms 够用」的同义词——真 kallsyms 命中是会给 `SymbolConfidence::Kallsyms`
/// 级可信度的 `Symbolized`；这里是不调 blazesym 时的**绝对最劣**实现：明确返错、
/// 不假装符号化成功、不给假数据。下游看到 `NotFound` 就知道**不能信这一帧**，
/// 走 §11 置信度 None 那档。
///
/// M1 第二刀接 blazesym 后本类型大概率删（或降级成「目标没内核符号表时的早期返错路径」）。
/// 单测可内插自己的 [`Symbolizer`] mock 跑通流程，不依赖本 fallback 的真实语义。
#[derive(Debug, Default, Clone, Copy)]
pub struct FallbackSymbolizer;

impl Symbolizer for FallbackSymbolizer {
    fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
        Err(SymbolizeError::NotFound {
            addr: format!("{addr:#x}"),
        })
    }
}

// ─── blazesym 路径（Linux cfg gate） ─────────────────────────────────────────
//
// 讨论 API 接入点：blazesym 0.2.5 暴露 `blazesym::symbolize::Symbolizer` +
// `Source` enum（含 `Kernel`/`Process` 变体） + `Input::AbsAddr(&[addr])`。
// 返回 `Vec<Symbolized>`，里头 `Symbolized::Sym(Sym{name, addr, offset,
// size: Option, code_info: Option<..>, inlined})` 或 `Symbolized::Unknown(_)`。
//
// Sym 没有显式 source 字段——§11 五档置信度要我们推断：
//   ① code_info.is_some() 且 line.is_some() → Dwarf（行号命中=DWARF 真回溯）
//   ② code_info.is_some()                    → Dwarf（至少文件命中）
//   ③ size.is_some()                          → Dynsym（ELF dynsym 给了 size）
//   ④ 其它 + name 非空                         → Kallsyms（只有符号名）
//   ⑤ Unknown 或 name 空                      → None
//
// M1 第二刀只是接入点的"骨架"，内核真路径（vmlinux path / kallsyms path / BTF）
// 在 M0 进靶机时一次性填（见 `BlazeSymbolizer::new_kernel` 的 TODO）。

#[cfg(target_os = "linux")]
pub mod blaze {
    use super::{SymbolizeError, Symbolizer};
    use introspect_schema::{SymbolConfidence, Symbolized};

    /// blazesym Symbolizer 的封装。
    ///
    /// 区分两种构造：进程态（ELF 文件路径，Mac 上 cfg 不让跑）+ 内核态
    /// （vmlinux/kallsyms 路径，M0 配齐）。
    ///
    /// 警告：blazesym 0.2.x API 偶尔漂。本结构只持 `blazesym::symbolize::Symbolizer`
    /// 一个字段——若 API 在 0.3 变了，只动这里。
    // TODO(M0 进靶机后)：一次性把 vmlinux / kallsyms / debug_syms / kaslr_offset 路径配置上来。
    pub struct BlazeSymbolizer {
        inner: blazesym::symbolize::Symbolizer,
    }

    impl BlazeSymbolizer {
        /// 给 ELF target 路径构造一个能做进程态符号化的 symbolizer。
        ///
        /// M1 第二刀的最小可调形态——Kernel 态留到 M0 配 vmlinux 再说。
        pub fn new_for_elf() -> Self {
            Self {
                inner: blazesym::symbolize::Symbolizer::new(),
            }
        }

        /// 内核态符号化（M0 才可调用）。
        // TODO(M0)：构造 `blazesym::symbolize::source::Kernel {
        //     kallsyms: MaybeDefault::Default,
        //     vmlinux: PathBuf::from("/usr/lib/debug/boot/vmlinux"),  // 靶机自装
        //     debug_syms: true, kaslr_offset: None, _non_exhaustive: (),
        // }` 并 wrap 在 BlazeSymbolizer 里走 Source::Kernel 调 path。
        pub fn new_kernel() -> Self {
            Self::new_for_elf()
        }
    }

    impl Symbolizer for BlazeSymbolizer {
        fn symbolize(&self, addr: u64) -> Result<Symbolized, SymbolizeError> {
            use blazesym::symbolize::{Input, Source};

            // M1 第二刀：进程态调用样例。Kernel 源头的 Source::Kernel 构造留 TODO(M0)，
            // 这里先走 Source::Process 占位，M0 在靶机度量后再切。
            // TODO(M0)：根据 BlazeSymbolizer 的构造模式分流 Source。
            let src = Source::Process(blazesym::symbolize::source::Process::new(
                std::process::id() as i32,
            ));
            let inputs = Input::AbsAddr(std::slice::from_ref(&addr));
            let results = self
                .inner
                .symbolize(&src, inputs)
                .map_err(|e| SymbolizeError::Backend { reason: e.to_string() })?;
            let sym = results.into_iter().next().ok_or(SymbolizeError::NotFound {
                addr: format!("{addr:#x}"),
            })?;
            blaze_to_symbolized(&sym)
        }

        /// §11 ① 双路交叉验证：拿 addr 符号化结果比对 expected_top_frame。
        /// 不匹配返 Some(reason)；匹配返 None（自洽，不降权）。
        fn cross_check(&self, addr: u64, expected_top_frame: &str) -> Option<String> {
            let sym = match self.symbolize(addr) {
                Ok(s) => s.name,
                Err(e) => return Some(format!("符号化失败：{e}")),
            };
            // §11：自洽的精确定义是顶帧符号与 wchan 指向同个函数或其紧邻调用栈帧。
            // M1 用最朴素口径——名字包含 expected_top_frame 前缀（去掉 +0x... 偏移后比对）。
            let sym_root = sym.split('+').next().unwrap_or(&sym);
            let expected = expected_top_frame.split('+').next().unwrap_or(expected_top_frame);
            if sym_root == expected {
                None
            } else {
                Some(format!("wchan/symbol={sym_root} 与 stack顶帧={expected} 不自洽"))
            }
        }
    }

    /// blazesym 返的 `Symbolized` → 我们 schema 的 `Symbolized` + §11 五档置信度。
    ///
    /// 真个 blazesym::symbolize::Symbolized 是个 enum (Sym(Unknown) Variant)，
    /// 这里用 & 入参以避免在 type 上 forward-declare 拷贝不来的偏特化。
    fn blaze_to_symbolized(
        s: &blazesym::symbolize::Symbolized,
    ) -> Result<Symbolized, SymbolizeError> {
        match s {
            blazesym::symbolize::Symbolized::Sym(sym) => {
                let name = sym.name.to_string();
                let offset = sym.addr;
                let conf = blaze_confidence(sym);
                Ok(Symbolized {
                    name: format!("{name}+0x{offset:x}"),
                    source: conf,
                })
            }
            blazesym::symbolize::Symbolized::Unknown(_) => Err(SymbolizeError::NotFound {
                addr: format!("{:#x}", 0usize),
            }),
        }
    }

    /// §11 五档置信度映射。按 §11 表②口径挑档：
    /// DWARF（带行号）→ DWARF、文件命中 → DWARF、size 有 → Dynsym、name 有 → Kallsyms、空 → None。
    fn blaze_confidence(sym: &blazesym::symbolize::Sym) -> SymbolConfidence {
        if let Some(info) = sym.code_info.as_ref() {
            if info.line.is_some() {
                return SymbolConfidence::Dwarf;
            }
            // 文件命中但没行号仍属 DWARF 同档——比 kallsyms 强
            return SymbolConfidence::Dwarf;
        }
        if sym.size.is_some() {
            return SymbolConfidence::Dynsym;
        }
        if !sym.name.is_empty() {
            return SymbolConfidence::Kallsyms;
        }
        SymbolConfidence::None
    }
}

/// 给单测造 Symbolized 数据用，绑定一档指定置信度。
#[cfg(test)]
pub fn make_symbolized(name: impl Into<String>, confidence: SymbolConfidence) -> Symbolized {
    Symbolized {
        name: name.into(),
        source: confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FallbackSymbolizer 在没 blazesym 时诚实返 NotFound ——不假装成功。
    /// §11 None 那档就是它落到下游的样子。
    #[test]
    fn fallback_symbolizer_returns_not_found() {
        let s = FallbackSymbolizer;
        let r = s.symbolize(0xffffffff81a2b3c4);
        match r {
            Err(SymbolizeError::NotFound { addr }) => {
                assert!(addr.contains("0x"), "addr 形态要含 0x 前缀: {addr}");
            }
            other => panic!("FallbackSymbolizer 必须 Err NotFound; 实际 {other:?}"),
        }
    }

    /// §11 ① cross_check 默认 None = 「没有交叉证据可判」时不强加降权。
    /// FallbackSymbolizer 走 trait 默认，所以这里钉住默认行为。
    #[test]
    fn fallback_cross_check_is_silent_none() {
        let s = FallbackSymbolizer;
        assert!(s.cross_check(0xdeadbeef, "anything").is_none());
    }

    /// 内插 mock Symbolizer 跑通 trait 调用路径——验证 trait 形状对路。
    /// 单测在意 mock，不在意 blazesym 真路径（Linux cfg gate 才编）。
    struct MockSym {}
    impl Symbolizer for MockSym {
        fn symbolize(&self, _addr: u64) -> Result<Symbolized, SymbolizeError> {
            Ok(make_symbolized("futex_wait_queue_me", SymbolConfidence::Kallsyms))
        }
        fn cross_check(&self, _addr: u64, expected_top_frame: &str) -> Option<String> {
            let sym = self.symbolize(0).unwrap().name;
            let sym_root = sym.split('+').next().unwrap_or(&sym);
            let expected_root = expected_top_frame.split('+').next().unwrap_or(expected_top_frame);
            if sym_root == expected_root {
                None
            } else {
                Some(format!("不自洽: sym={sym_root} expected={expected_root}"))
            }
        }
    }

    #[test]
    fn mock_symbolizer_cross_check_self_consistent() {
        let s = MockSym {};
        // wchan 给 "futex_wait_queue_me+0x12"，顶帧也给同个 root → 自洽
        assert!(s.cross_check(0x1, "futex_wait_queue_me+0x12").is_none());
    }

    #[test]
    fn mock_symbolizer_cross_check_inconsistent() {
        let s = MockSym {};
        assert!(s.cross_check(0x1, "schedule+0x40").is_some());
    }
}
