//! 宿主侧审计 sink（§13.6）。
//!
//! §13.6 三条硬要求：
//!   1. append-only — AI 改不了已 ship 的；
//!   2. JSON lines —— 可 grep 可投影 (token 友好)；
//!   3. 两流分开 —— 意图流 (每条决策完整) + 效果流 (采样运行时统计)。
//!
//! 本模块只定 **意图流** sink 的 trait + 内存实现。效果流 M6 探针在位后单独建模，
//! 这里不混进来 (§13.6 明写)。

use async_trait::async_trait;
use std::sync::Mutex;
use vsock::model::AuditEvent;

/// append-only 意图审计 sink 行为。
///
/// M5 之前这些都是 trait 在位、实现纳真（M5 起）。 trait 的形状现在就钉死 =
/// 让 §13.9 那 M5 一刀到代码里时不需要重改 vsock 的 schema。
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// append 一条意图事件。 返回该 sink 内部分配的稳定序号 (供回溯审计用)。
    /// 实现要保证**写后不可改**(append-only)； §13.6 这是公理 7 的落地。
    async fn append(&self, event: AuditEvent) -> Result<u64, AuditSinkError>;
}

/// sink 失败模式。
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    #[error("append-only sink 写入失败：{0}")]
    Write(String),
}

/// 单测用内存实现。生产侧换文件/数据库 (M5)。
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    /// 取写入的全部事件快照 (单测就緒性断言用)。
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn append(&self, event: AuditEvent) -> Result<u64, AuditSinkError> {
        let mut v = self.events.lock().unwrap();
        let seq = event.seq;
        v.push(event);
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vsock::model::{IntentRecord, Owner};

    fn make_event(seq: u64) -> AuditEvent {
        AuditEvent {
            seq,
            ts: Utc::now(),
            intent: IntentRecord::ReadProc {
                pid: 1,
                owner: Owner::Ai,
            },
        }
    }

    #[tokio::test]
    async fn append_is_in_order_and_persistent() {
        let sink = InMemoryAuditSink::new();
        for s in [1u64, 2, 3] {
            sink.append(make_event(s)).await.unwrap();
        }
        let got = sink.snapshot();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].seq, 1);
        assert_eq!(got[2].seq, 3);
    }
}
