//! host-supervisor：宿主侧可信控制面（§13.2 / §13.3）。
//!
//! §13.3「控制面小、简单、可穷尽测试」——本 crate 的 trait 与空壳定位是
//! **trait 位置先在位**（M5 之前许多能力都用不上），让 §13.9 里程碑 M5 那刀
//! 「安全脚手架先于写能力」落到代码里时**已经有位置可以填**。
//!
//! 组件：审计 sink（append-only 意图接收） / 人审门 / 仲裁器 / VM 快照控制。
//! M5 是这些 trait 第一次实现纳真；本 crate M0-M4 阶段只建 trait + stub。
//!
//! **依赖卫生**：host-supervisor 依赖 [`vsock`]（既收审计、又下发 Request），
//!   依赖 [`introspect_schema`]（跨边界 Level0 解码）——这两个都是叶子 scholarship，
//!   无环。**不依赖 guest-agent** —— 和 guest-agent 间只通过 vsock 上的 Message 相互形状，
//!   跨边界契约由 schema crate 锁死，不靠 crate 互引。

pub mod audit;
pub mod gate;

pub use audit::{AuditSink, InMemoryAuditSink};
pub use gate::{GateDecision, HumanGate, LkmParamGate};

pub use vsock as transport;
