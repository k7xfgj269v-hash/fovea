//! Directional messages crossing the host/guest trust boundary.
//!
//! The trusted host sends capability requests. The untrusted guest can return
//! responses, execution receipts, and effect telemetry, but no host intent
//! record is representable in this module.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chrono::{DateTime, Utc};
use introspect_schema::Level0;

/// Messages the trusted host can send to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostToGuest {
    Request(Request),
}

/// Untrusted evidence the guest can send to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// `Response` carries the intentionally unboxed Level0 wire payload.
#[allow(clippy::large_enum_variant)]
pub enum GuestToHost {
    Response(Response),
    ExecutionReceipt(ExecutionReceipt),
    EffectTelemetry(EffectTelemetry),
}

// ─── Request ──────────────────────────────────────────────────────────────────

/// 宿主侧下发给 guest-agent 的能力调用（§13.8 能力面）。
///
/// `id` 用于把 Response 配对回 Request——vsock 是异步全双工的，请求 1 的响应
/// 可能比请求 2 的响应晚到，靠 id 配对而非靠到达顺序。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
// Boxing the success payload would change the pre-1.0 JSON contract.
#[allow(clippy::large_enum_variant)]
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

// ─── Guest evidence ──────────────────────────────────────────────────────────

/// Guest-observed execution timing and outcome for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub request_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: ExecutionOutcome,
}

/// The guest's claim about whether request execution completed successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    Failed { error: ErrorReport },
}

/// Guest-observed side-effect samples for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectTelemetry {
    pub request_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub samples: Vec<EffectSample>,
    pub dropped_samples: u64,
}

/// One named telemetry measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSample {
    pub name: String,
    pub value: u64,
    pub unit: String,
}

// ─── ErrorReport ─────────────────────────────────────────────────────────────

/// §2.2「报错是散文 + 退出码」翻转成「结构化错误：类型 + 原因 + 建议下一步」。
///
/// 出现在 Response::Err，也出现在 guest-agent 给 AI 出口的所有失败路径上。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

// ─── Correlation helpers ─────────────────────────────────────────────────────

impl Response {
    pub fn req_id(&self) -> Uuid {
        match self {
            Response::Ok { req_id, .. } => *req_id,
            Response::Err { req_id, .. } => *req_id,
        }
    }
}

impl GuestToHost {
    /// Return the request ID carried by every guest evidence variant.
    pub fn request_id(&self) -> Uuid {
        match self {
            GuestToHost::Response(response) => response.req_id(),
            GuestToHost::ExecutionReceipt(receipt) => receipt.request_id,
            GuestToHost::EffectTelemetry(telemetry) => telemetry.request_id,
        }
    }
}

// ─── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn request_body_side_effect_matches_doc() {
        // §13.8：introspect Level 0 = read → 无门
        let b = RequestBody::Introspect { pid: 1 };
        assert_eq!(b.side_effect(), SideEffect::Read);
    }

    #[test]
    fn retained_request_wire_shape_is_unchanged() {
        let request = Request {
            id: Uuid::nil(),
            body: RequestBody::Introspect { pid: 1 },
        };

        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "id": Uuid::nil(),
                "body": {"verb": "introspect", "pid": 1}
            })
        );
    }

    #[test]
    fn host_to_guest_request_has_exact_direction_tag() {
        let message = HostToGuest::Request(Request {
            id: Uuid::nil(),
            body: RequestBody::Introspect { pid: 1 },
        });

        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "request",
                "id": Uuid::nil(),
                "body": {"verb": "introspect", "pid": 1}
            })
        );

        let decoded: HostToGuest = serde_json::from_value(value).unwrap();
        match decoded {
            HostToGuest::Request(request) => {
                assert_eq!(request.id, Uuid::nil());
                assert!(matches!(request.body, RequestBody::Introspect { pid: 1 }));
            }
        }
    }

    #[test]
    fn response_variants_keep_exact_wire_shape_and_request_id() {
        let ok = GuestToHost::Response(Response::Ok {
            req_id: Uuid::nil(),
            body: ResponseBody::Introspect(sample_level0()),
        });
        let ok_value = serde_json::to_value(&ok).unwrap();
        assert_eq!(ok_value["kind"], "response");
        assert_eq!(ok_value["status"], "ok");
        assert_eq!(ok_value["req_id"], Uuid::nil().to_string());
        assert_eq!(ok_value["verb"], "introspect");
        assert!(ok_value.get("identity").is_some());
        assert_eq!(ok.request_id(), Uuid::nil());
        assert_eq!(
            serde_json::from_value::<GuestToHost>(ok_value)
                .unwrap()
                .request_id(),
            Uuid::nil()
        );

        let err = GuestToHost::Response(Response::Err {
            req_id: Uuid::nil(),
            error: ErrorReport::new("proc_not_found", "no such pid")
                .with_next_step("check whether the process is still alive"),
        });
        let err_value = serde_json::to_value(&err).unwrap();
        assert_eq!(
            err_value,
            json!({
                "kind": "response",
                "status": "err",
                "req_id": Uuid::nil(),
                "error": {
                    "type": "proc_not_found",
                    "reason": "no such pid",
                    "next_step": "check whether the process is still alive"
                }
            })
        );
        assert_eq!(err.request_id(), Uuid::nil());
        assert_eq!(
            serde_json::from_value::<GuestToHost>(err_value)
                .unwrap()
                .request_id(),
            Uuid::nil()
        );
    }

    #[test]
    fn execution_receipt_success_has_exact_wire_shape() {
        let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let message = GuestToHost::ExecutionReceipt(ExecutionReceipt {
            request_id: Uuid::nil(),
            started_at: at,
            finished_at: at,
            outcome: ExecutionOutcome::Succeeded,
        });

        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "execution_receipt",
                "request_id": Uuid::nil(),
                "started_at": "2023-11-14T22:13:20Z",
                "finished_at": "2023-11-14T22:13:20Z",
                "outcome": {"status": "succeeded"}
            })
        );
        assert_eq!(
            serde_json::from_value::<GuestToHost>(value)
                .unwrap()
                .request_id(),
            Uuid::nil()
        );
    }

    #[test]
    fn execution_receipt_failure_has_exact_wire_shape() {
        let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let message = GuestToHost::ExecutionReceipt(ExecutionReceipt {
            request_id: Uuid::nil(),
            started_at: at,
            finished_at: at,
            outcome: ExecutionOutcome::Failed {
                error: ErrorReport::new("proc_not_found", "no such pid"),
            },
        });

        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "execution_receipt",
                "request_id": Uuid::nil(),
                "started_at": "2023-11-14T22:13:20Z",
                "finished_at": "2023-11-14T22:13:20Z",
                "outcome": {
                    "status": "failed",
                    "error": {
                        "type": "proc_not_found",
                        "reason": "no such pid",
                        "next_step": null
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<GuestToHost>(value)
                .unwrap()
                .request_id(),
            Uuid::nil()
        );
    }

    #[test]
    fn effect_telemetry_has_exact_wire_shape() {
        let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let message = GuestToHost::EffectTelemetry(EffectTelemetry {
            request_id: Uuid::nil(),
            observed_at,
            samples: vec![EffectSample {
                name: "syscalls".to_owned(),
                value: 7,
                unit: "count".to_owned(),
            }],
            dropped_samples: 2,
        });

        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "effect_telemetry",
                "request_id": Uuid::nil(),
                "observed_at": "2023-11-14T22:13:20Z",
                "samples": [
                    {"name": "syscalls", "value": 7, "unit": "count"}
                ],
                "dropped_samples": 2
            })
        );
        assert_eq!(
            serde_json::from_value::<GuestToHost>(value)
                .unwrap()
                .request_id(),
            Uuid::nil()
        );
    }

    #[test]
    fn legacy_guest_audit_event_is_rejected() {
        let error = serde_json::from_value::<GuestToHost>(json!({
            "kind": "audit_event",
            "seq": 1,
            "ts": "2023-11-14T22:13:20Z",
            "intent": {
                "kind": "read_proc",
                "pid": 1,
                "owner": "ai"
            }
        }))
        .unwrap_err();

        assert!(error.to_string().contains("unknown variant"));
    }

    fn sample_level0() -> Level0 {
        serde_json::from_value(json!({
            "identity": {
                "pid": 1,
                "comm": "init",
                "exe": null,
                "cmdline": {"short": "init", "full_len": 4},
                "uid": 0,
                "cgroup": null
            },
            "state": {
                "run_state": "S",
                "last_cpu": 0,
                "nr_threads": 1,
                "wchan": null
            },
            "resource": {
                "rss_bytes": 0,
                "vsz_bytes": 0,
                "nr_fds": 0,
                "pct_cpu": 0.0,
                "ctxt_switches": {"voluntary": 0, "nonvoluntary": 0}
            },
            "mem_shape": {"histogram": [], "top_n": []},
            "hotspot": {"kind": "not_blocked"},
            "recent": {"kind": "recorder_off"},
            "confidence": {"overall": 1.0, "low_fields": []},
            "handles": {
                "threads": null,
                "maps": null,
                "stack": null,
                "fds": null,
                "env": null,
                "symbols": null
            },
            "cost_hint": {
                "token": 0,
                "api_cost": null,
                "overhead_est_ns": 0
            }
        }))
        .unwrap()
    }
}
