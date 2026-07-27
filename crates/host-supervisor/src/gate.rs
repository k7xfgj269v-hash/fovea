//! 人审门（§5.2 / §13.8 副作用等级路由）。
//!
//! §13.8 把门按副作用等级分三道：
//!   1. `read` —— 无门；
//!   2. `dry-runnable-write` —— dry-run → 确认；
//!   3. `intervention` —— **事前** verifier (机器, 挡崩溃) + **事前** 人审门 hook
//!      (机械 def: 默认放行, 可一键切人审, §13.9 M5 公理 14 的非 form-only 那道) +
//!      **事后** 效果审计 + 被动可发现；
//!   4. `kernel-write` —— 人审门 (参数审查，§5.2)；
//!   5. `irreversible` —— 显式确认 + 审计。
//!
//! 公理 14「verifier ≠ 授权门」分离点在这里：verifier 证明 "不崩"，本 trait 这种 gate
//! 证明 「该做」。M5 那一刀会把本 trait 纳真; 这阶段只占 trait 位置。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// 门落的决定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateDecision {
    /// 放行 (无门 / 默认放行的 intervention hook)。
    Allow,
    /// 等待人审批 (typ: kernel-write 强制人审 / intervention 切人审模式)。
    PendingHuman,
    /// 拒绝 (审参数过不去 / 人按 deny)。
    Deny { reason: String },
}

/// §13.8 副作用路由里的**人审门**抽象。
///
/// 因 intervention 那道 §13.9 M5 「事前 hook，默认放行」有**两种行为**:
///   - 干预类总是过 verifier (机器), 之后再被本 gate 二次卡 (默认放行 / 可切人审);
///   - kernel-write 类**不走 verifier** (它不是 BPF), 直接入本 gate, 安全网只有人审。
///
/// 这两者都属 `trait HumanGate`不同实现。二变体用 [`GateKind`] 区分。
#[async_trait]
pub trait HumanGate: Send + Sync {
    async fn decide(&self, kind: GateKind) -> GateDecision;
}

/// §13.8 副作用等级路由里走人审门的两类 (另三类不在本 trait: read 无门 /
/// dry-runnable-write 由调用方先 dry-run, irreversible 单独显式确认)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateKind {
    /// §13.8 `intervention` —— M5 hook 默认放行, 可切人审。
    Intervention,
    /// §13.8 `kernel-write` —— LKM 参数化模块走强制人审 (§5.2)。
    LkmParam,
}

/// LKM 参数化模块的人审门具象类型 —— M9 那一刻纳真。M1 占位。
///
/// §5.2「LKM 侧信任边界在参数不在代码：审参数 ≫ 审生成的 C」—— gate 检的对象是
/// 参数表, 不是模块源码。这条原则决定本 trait 方法签名设计 (TODO M9 时落实)。
pub struct LkmParamGate;

#[async_trait]
impl HumanGate for LkmParamGate {
    async fn decide(&self, _kind: GateKind) -> GateDecision {
        // M9 落实时改成真审参数；现在占位 Allow 也不破坏 §13.9 公理 13,
        // 因为公理 13 是 "脚手架不先发" —— 这个席位先在位、未接写能力时纯 No-op。
        GateDecision::Allow
    }
}
