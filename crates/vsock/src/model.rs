//! 跨 vsock 走的消息形状（§13.2 拓扑 + §13.6 审计 sink）。
//!
//! 三类东西跨信任边界：
//!   1. **Request** —— 宿主 → 靶机，调能力（§13.8 能力面）。M1 阶段只有 `Introspect`。
//!   2. **Response** —— 靶机 → 宿主，请求的回执。M1 阶段是 `Level0` 快照（§10）。
//!   3. **AuditEvent** —— 靶机 → 宿主，单向 append-only 流，每条决策一份（§13.6 意图流）。
//!
//! 设计要点：**审计是单向的、与请求响应分离的流**（§13.6「两流分开」）。
//! 这是公理 7（信任边界坐宿主侧）的落地形态：靶机侧 AI 即便完全接管 guest-agent，
//! 也改不了已经 ship 到宿主的审计。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chrono::{DateTime, Utc};
use introspect_schema::Level0;

/// vsock 上的信封。三种载荷二选一不能同时混。
///
/// 之所以不分成三个 trait，是因为它们共享同一条 vsock 链路、共享 framing，
/// 而控制面 task 有时按一条逻辑处理「先 recv 一条 Request，再 ship 一条 AuditEvent」，
/// 一个 enum 比三个独立 channel 更贴合物理事实。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Message {
    Request(Request),
    Response(Response),
    AuditEvent(AuditEvent),
}

// ─── Request ──────────────────────────────────────────────────────────────────

/// 宿主侧下发给 guest-agent 的能力调用（§13.8 能力面）。
///
/// `id` 用于把 Response 配对回 Request——vsock 是异步全双工的，请求 1 的响应
/// 可能比请求 2 的响应晚到，靠 id 配对而非靠到达顺序。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: Uuid,
    pub body: RequestBody,
}

/// 能力面 body。随里程碑扩张：
/// - M1: 只有 `Introspect`（§10）
/// - M6: 加 `AttachProbe`（§13.5）
/// - M7: 加 `ConfigIntervention`（§13.5 干预类，过 §13.8 `intervention` 门）
/// - M8: 加 `FsTransaction` 系列
/// - M9: 加 `LoadLkmPrimitive`（§5.2/§5.3，过 §13.8 `kernel-write` 人审门）
///
/// 副作用等级（§13.8）直接落在每个 variant 旁的注释里，方便 host-supervisor
/// 的门（§8.2）按副作用等级路由：read 无门、intervention 走事前门、kernel-write 走人审门。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RequestBody {
    /// §10。`read` —— 无门（§13.8）。
    Introspect { pid: i32 },

    // TODO(M6): AttachProbe { probe: ProbeSpec } —— 副作用 `intervention` 一旦
    // 探针改返回值，read 不再纯；定为 `intervention`，走 §13.8 事前门。
    // TODO(M7): ConfigIntervention { probe_id: .., override: .. } —— `intervention`。
    // TODO(M8): FsBegin / FsStage / FsCommit —— `dry-runnable-write`。
    // TODO(M9): LoadLkmPrimitive { module: .., params: .. } —— `kernel-write`，人审门。
}

impl RequestBody {
    /// §13.8 副作用等级。host-supervisor 的门按这个值决定路由。
    ///
    /// 「verifier ≠ 授权门」（公理 14）：副作用等级是授权侧的事，
    /// verifier 只挡崩溃、不挡语义，两者协作而非替代。
    pub fn side_effect(&self) -> SideEffect {
        match self {
            RequestBody::Introspect { .. } => SideEffect::Read,
        }
    }
}

/// §13.8 五档副作用等级。host-supervisor 的「门」按此路由。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    /// 纯读（introspect Level 0）。无门。
    Read,
    /// 可预览 diff 再执行（fs 写）。门 = dry-run → 确认。
    DryRunnableWrite,
    /// eBPF 干预（改现实）。门 = 事前 verifier + 事前门 hook + 事后效果审计 + 被动可发现。
    Intervention,
    /// LKM 原语模块。门 = 人审门（参数，§5.2）。
    KernelWrite,
    /// 不可撤（§9 残余）。门 = 显式确认 + 审计。
    Irreversible,
}

// ─── Response ─────────────────────────────────────────────────────────────────

/// 靶机对宿主请求的回执。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        req_id: Uuid,
        #[serde(flatten)]
        body: ResponseBody,
    },
    Err {
        req_id: Uuid,
        /// 结构化错误（§2.2）：类型 + 原因 + 建议下一步。
        error: ErrorReport,
    },
}

/// 成功响应的 body。与 RequestBody 一一对应。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ResponseBody {
    /// §10 / §13.4。Level 0 全部来自 /proc 解析 + blazesym 符号化，零探针。
    Introspect(Level0),
}

// ─── AuditEvent ──────────────────────────────────────────────────────────────

/// §13.6 意图流的一条记录。append-only，ship 到宿主 sink，AI 改不了。
///
/// 注意：**意图流和效果流分开**（§13.6 两流分开）。这里只定义意图流；效果流
/// （采样运行时统计）等 M6 探针在位后单独建模，这里不混进来。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 全局递增序号。宿侧 sink 校验连续性——断序 = 丢了 ship，可疑。
    pub seq: u64,
    /// 事件时间戳（UTC，ISO 8601）。
    pub ts: DateTime<Utc>,
    /// 意图本体。
    pub intent: IntentRecord,
}

impl AuditEvent {
    pub fn new(seq: u64, intent: IntentRecord) -> Self {
        Self {
            seq,
            ts: Utc::now(),
            intent,
        }
    }
}

/// 意图本体。每次「agent 做了一个决策」记一份（§13.6 意图流）。
///
/// M1 阶段只有 `ReadProc`——即便它是 read、没写能力，**意图审计的习惯在 M1 就埋**，
/// 这是公理 13「安全脚手架先于写能力」在 M1 这一最小实例上的体现：
/// 脚手架本身先在位，写能力来了直接复用同一条 ship 路径。
///
/// 后续里程碑按 §13.5 探针生命周期追加：
/// - M6/M7: `AttachProbe` / `DetachProbe` / `ConfigIntervention`
/// - M9: `LoadLkmPrimitive` / `UnloadLkmPrimitive`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntentRecord {
    /// 调了 `introspect(pid)`。
    ReadProc {
        pid: i32,
        /// owner=AI：本调用由 AI 发起。
        /// owner=human 不会出现——人走 shell 不走这条 vsock，但本字段保留，
        /// 供未来「宿主侧链路也让 AI 起请求」时区分。
        owner: Owner,
    },
}

impl IntentRecord {
    /// 给单测造数据用，不代表真实语义。
    #[cfg(test)]
    pub fn sample() -> Self {
        IntentRecord::ReadProc {
            pid: 42,
            owner: Owner::Ai,
        }
    }
}

/// 决策发起者。AI 决策必须留痕——公理 9（人默认可见、干预类被动可发现）的前置。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Ai,
    Human,
}

// ─── ErrorReport ─────────────────────────────────────────────────────────────

/// §2.2「报错是散文 + 退出码」翻转成「结构化错误：类型 + 原因 + 建议下一步」。
///
/// 出现在 Response::Err，也出现在 guest-agent 给 AI 出口的所有失败路径上。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    /// 错误类型，机器可分支。e.g. `proc_not_found` / `symbolize_failed` / `vsock_peer_closed`。
    #[serde(rename = "type")]
    pub kind: String,
    /// 人/AI 可读原因。
    pub reason: String,
    /// 建议下一步（§2.2）。可选——某些错（vsock 关闭）没有合理的下一步。
    pub next_step: Option<String>,
}

impl ErrorReport {
    pub fn new(kind: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            reason: reason.into(),
            next_step: None,
        }
    }

    pub fn with_next_step(mut self, step: impl Into<String>) -> Self {
        self.next_step = Some(step.into());
        self
    }
}

// ─── 给 host-supervisor 用的辅助：response 配对 ─────────────────────────────

impl Response {
    pub fn req_id(&self) -> Uuid {
        match self {
            Response::Ok { req_id, .. } => *req_id,
            Response::Err { req_id, .. } => *req_id,
        }
    }
}

impl Message {
    /// 若是 Response，返回其 req_id；否则 None。给宿主侧请求 / 响应 multiplexer 用。
    pub fn req_id(&self) -> Option<Uuid> {
        match self {
            Message::Response(r) => Some(r.req_id()),
            _ => None,
        }
    }

    /// 若是 AuditEvent，返回其 seq；否则 None。给宿侧审计 sink 校验连续性用。
    pub fn audit_seq(&self) -> Option<u64> {
        match self {
            Message::AuditEvent(e) => Some(e.seq),
            _ => None,
        }
    }
}

// ─── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_side_effect_matches_doc() {
        // §13.8：introspect Level 0 = read → 无门
        let b = RequestBody::Introspect { pid: 1 };
        assert_eq!(b.side_effect(), SideEffect::Read);
    }

    #[test]
    fn message_serializes_as_json_lines_friendly() {
        // §13.6：JSON lines。一条消息一行——序列化结果不能含裸换行（否则 framing 坏）。
        let m = Message::Request(Request {
            id: Uuid::nil(),
            body: RequestBody::Introspect { pid: 1 },
        });
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains('\n'), "消息序列化结果含裸换行，会破坏 framing");
        // 反序列化回来要等价
        let m2: Message = serde_json::from_str(&s).unwrap();
        match m2 {
            Message::Request(r) => {
                assert_eq!(r.id, Uuid::nil());
                match r.body {
                    RequestBody::Introspect { pid } => assert_eq!(pid, 1),
                }
            }
            _ => panic!("tag 不匹配"),
        }
    }

    #[test]
    fn error_report_round_trip() {
        let e = ErrorReport::new("proc_not_found", "no such pid")
            .with_next_step("确认 pid 仍存活；可用 introspect(pid=1) 探一下");
        let s = serde_json::to_string(&e).unwrap();
        let e2: ErrorReport = serde_json::from_str(&s).unwrap();
        assert_eq!(e2.kind, "proc_not_found");
        assert!(e2.next_step.is_some());
    }
}
