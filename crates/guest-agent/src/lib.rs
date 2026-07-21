//! guest-agent：靶机侧 agent（不可信侧）。
//!
//! §13.2 / §13.3 拓扑：
//! - 数据面 / 不可信——AI 接管了它，也改不了已 ship 到宿主侧的审计；
//! - 组件：MCP front（M2 起） / 内省引擎（M1） / probe manager（M6+） /
//!   飞行记录（M4） / 写侧（eBPF M6-7 + LKM M9）。
//!
//! M1 阶段只开 **introspect 原语** 的 pure-Rust crate 形态：proc 解析逻辑走 [`proc_view`]，
//! 符号化走 [`symbolize`]。这两个模块就是 §13.4 Level 0 的落地引擎——
//! 「GB maps → 十几行」就是在这里被压出来的。
//!
//! **依赖卫生**：本 crate 依赖 [`introspect_schema`]（消费 Level0 形状），
//! **不依赖 [`vsock`]**——vsock 是宿主侧→靶机侧传输层，单向穿过 crate 拓扑，
//! 让 guest-agent 反过来 dep `vsock` 就会形成循环。靶机侧要把审计 ship 出去，
//! 通过 trait 接口由调用方（M2 MCP server shell）注入 Transport，不要把传输层塞进来。

pub mod introspect;
pub mod proc_view;
pub mod symbolize;

pub use introspect::{introspect, introspect_with, introspect_with_inputs};

pub use introspect_schema as schema;
