//! Host-owned append-only intent and outcome audit streams.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vsock::{
    model::{Request, RequestBody, SideEffect},
    TransportError,
};

use crate::gate::GateDecision;

/// Result of the host budget evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetDecision {
    Allow,
    Deny { reason: String },
}

/// Whether the host authorizes transport dispatch after budget and gate checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchDecision {
    Dispatch,
    DoNotDispatch,
}

impl DispatchDecision {
    fn from_decisions(budget: &BudgetDecision, gate: &GateDecision) -> Self {
        if matches!(budget, BudgetDecision::Allow) && matches!(gate, GateDecision::Allow) {
            Self::Dispatch
        } else {
            Self::DoNotDispatch
        }
    }
}

/// Host intent before the sink allocates its sequence and timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewIntentRecord {
    pub request_id: Uuid,
    pub request: RequestBody,
    pub side_effect: SideEffect,
    pub budget: BudgetDecision,
    pub gate: GateDecision,
    pub dispatch: DispatchDecision,
}

impl NewIntentRecord {
    /// Build an intent from the request body and host decisions.
    pub fn from_request(request: &Request, budget: BudgetDecision, gate: GateDecision) -> Self {
        let dispatch = DispatchDecision::from_decisions(&budget, &gate);

        Self {
            request_id: request.id,
            request: request.body.clone(),
            side_effect: request.body.side_effect(),
            budget,
            gate,
            dispatch,
        }
    }
}

/// Sequenced host authority record.
///
/// Guest evidence cannot construct this record as a protocol message:
///
/// ```compile_fail
/// use host_supervisor::audit::IntentAuditRecord;
/// use vsock::model::GuestToHost;
///
/// fn forge(record: IntentAuditRecord) -> GuestToHost {
///     GuestToHost::IntentAuditRecord(record)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentAuditRecord {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub request_id: Uuid,
    pub request: RequestBody,
    pub side_effect: SideEffect,
    pub budget: BudgetDecision,
    pub gate: GateDecision,
    pub dispatch: DispatchDecision,
}

/// A host-observed failure after an intent was appended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostOutcome {
    TransportFailure {
        error: TransportError,
    },
    ProtocolCorrelationFailure {
        expected_request_id: Uuid,
        received_request_id: Uuid,
    },
}

/// Host outcome stream entry supplied by the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostOutcomeRecord {
    pub request_id: Uuid,
    pub ts: DateTime<Utc>,
    pub outcome: HostOutcome,
}

/// Append-only host audit port.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn append_intent(
        &self,
        record: NewIntentRecord,
    ) -> Result<IntentAuditRecord, AuditSinkError>;

    async fn append_outcome(&self, record: HostOutcomeRecord) -> Result<u64, AuditSinkError>;
}

/// Audit sink failure.
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    #[error("append-only sink write failed: {0}")]
    Write(String),
    #[error("{stream} audit stream lock is poisoned")]
    Poisoned { stream: &'static str },
    #[error("{stream} audit sequence is exhausted")]
    SequenceExhausted { stream: &'static str },
}

/// In-memory append-only sink with independent intent and outcome streams.
pub struct InMemoryAuditSink {
    intents: Mutex<Vec<IntentAuditRecord>>,
    outcomes: Mutex<Vec<(u64, HostOutcomeRecord)>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            outcomes: Mutex::new(Vec::new()),
        }
    }

    /// Return a copy of the authoritative intent stream.
    pub fn intent_snapshot(&self) -> Result<Vec<IntentAuditRecord>, AuditSinkError> {
        self.intents
            .lock()
            .map(|records| records.clone())
            .map_err(|_| AuditSinkError::Poisoned { stream: "intent" })
    }

    /// Return a copy of the separately sequenced host outcome stream.
    pub fn outcome_snapshot(&self) -> Result<Vec<(u64, HostOutcomeRecord)>, AuditSinkError> {
        self.outcomes
            .lock()
            .map(|records| records.clone())
            .map_err(|_| AuditSinkError::Poisoned { stream: "outcome" })
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn append_intent(
        &self,
        record: NewIntentRecord,
    ) -> Result<IntentAuditRecord, AuditSinkError> {
        let mut records = self
            .intents
            .lock()
            .map_err(|_| AuditSinkError::Poisoned { stream: "intent" })?;
        let seq = next_sequence(records.len(), "intent")?;
        let NewIntentRecord {
            request_id,
            request,
            side_effect,
            budget,
            gate,
            dispatch,
        } = record;
        let record = IntentAuditRecord {
            seq,
            ts: Utc::now(),
            request_id,
            request,
            side_effect,
            budget,
            gate,
            dispatch,
        };
        records.push(record.clone());
        Ok(record)
    }

    async fn append_outcome(&self, record: HostOutcomeRecord) -> Result<u64, AuditSinkError> {
        let mut records = self
            .outcomes
            .lock()
            .map_err(|_| AuditSinkError::Poisoned { stream: "outcome" })?;
        let seq = next_sequence(records.len(), "outcome")?;
        records.push((seq, record));
        Ok(seq)
    }
}

fn next_sequence(len: usize, stream: &'static str) -> Result<u64, AuditSinkError> {
    u64::try_from(len)
        .ok()
        .and_then(|seq| seq.checked_add(1))
        .ok_or(AuditSinkError::SequenceExhausted { stream })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;
    use vsock::model::GuestToHost;

    fn request(request_id: Uuid, pid: i32) -> Request {
        Request {
            id: request_id,
            body: RequestBody::Introspect { pid },
        }
    }

    fn allowed_intent(request_id: Uuid, pid: i32) -> NewIntentRecord {
        NewIntentRecord::from_request(
            &request(request_id, pid),
            BudgetDecision::Allow,
            GateDecision::Allow,
        )
    }

    fn outcome(request_id: Uuid) -> HostOutcomeRecord {
        HostOutcomeRecord {
            request_id,
            ts: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            outcome: HostOutcome::TransportFailure {
                error: TransportError::PeerClosed,
            },
        }
    }

    #[test]
    fn intent_derives_authoritative_side_effect_and_dispatch_decision() {
        let request_id = Uuid::new_v4();
        let allowed = allowed_intent(request_id, 1);
        assert_eq!(allowed.request_id, request_id);
        assert_eq!(allowed.side_effect, SideEffect::Read);
        assert_eq!(allowed.dispatch, DispatchDecision::Dispatch);

        let denied = NewIntentRecord::from_request(
            &request(request_id, 1),
            BudgetDecision::Deny {
                reason: "budget exhausted".to_owned(),
            },
            GateDecision::Allow,
        );
        assert_eq!(denied.side_effect, SideEffect::Read);
        assert_eq!(denied.dispatch, DispatchDecision::DoNotDispatch);

        let pending = NewIntentRecord::from_request(
            &request(request_id, 1),
            BudgetDecision::Allow,
            GateDecision::PendingHuman,
        );
        assert_eq!(pending.dispatch, DispatchDecision::DoNotDispatch);
    }

    #[tokio::test]
    async fn intent_and_outcome_streams_allocate_independent_sequences() {
        let sink = InMemoryAuditSink::new();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();

        let first_intent = sink
            .append_intent(allowed_intent(first_id, 1))
            .await
            .unwrap();
        let first_outcome_seq = sink.append_outcome(outcome(first_id)).await.unwrap();
        let second_intent = sink
            .append_intent(allowed_intent(second_id, 2))
            .await
            .unwrap();
        let second_outcome_seq = sink.append_outcome(outcome(second_id)).await.unwrap();

        assert_eq!(first_intent.seq, 1);
        assert_eq!(second_intent.seq, 2);
        assert_eq!(first_outcome_seq, 1);
        assert_eq!(second_outcome_seq, 2);

        let intents = sink.intent_snapshot().unwrap();
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].request_id, first_id);
        assert_eq!(intents[1].request_id, second_id);

        let outcomes = sink.outcome_snapshot().unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].0, 1);
        assert_eq!(outcomes[0].1.request_id, first_id);
        assert_eq!(outcomes[1].0, 2);
        assert_eq!(outcomes[1].1.request_id, second_id);
    }

    #[tokio::test]
    async fn returned_snapshots_cannot_mutate_appended_records() {
        let sink = InMemoryAuditSink::new();
        let request_id = Uuid::new_v4();
        sink.append_intent(allowed_intent(request_id, 1))
            .await
            .unwrap();
        sink.append_outcome(outcome(request_id)).await.unwrap();

        let mut intents = sink.intent_snapshot().unwrap();
        let mut outcomes = sink.outcome_snapshot().unwrap();
        intents.clear();
        outcomes.clear();

        assert_eq!(sink.intent_snapshot().unwrap().len(), 1);
        assert_eq!(sink.outcome_snapshot().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn host_audit_records_round_trip_but_are_rejected_as_guest_evidence() {
        let sink = InMemoryAuditSink::new();
        let intent = sink
            .append_intent(allowed_intent(Uuid::nil(), 1))
            .await
            .unwrap();
        let intent_json = serde_json::to_value(&intent).unwrap();
        assert_eq!(
            serde_json::from_value::<IntentAuditRecord>(intent_json.clone()).unwrap(),
            intent
        );
        assert!(serde_json::from_value::<GuestToHost>(intent_json).is_err());

        let host_outcome = outcome(Uuid::nil());
        let outcome_json = serde_json::to_value(&host_outcome).unwrap();
        assert_eq!(
            serde_json::from_value::<HostOutcomeRecord>(outcome_json).unwrap(),
            host_outcome
        );
    }

    #[test]
    fn legacy_guest_audit_evidence_is_rejected() {
        assert!(serde_json::from_value::<GuestToHost>(json!({
            "kind": "audit_event",
            "seq": 1,
            "ts": "2023-11-14T22:13:20Z",
            "intent": {
                "kind": "read_proc",
                "pid": 1,
                "owner": "ai"
            }
        }))
        .is_err());
    }
}
