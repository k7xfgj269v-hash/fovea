//! host-supervisor: trusted host-side control plane.
//!
//! Host authority, including budget, gate, dispatch, and audit decisions,
//! remains separate from untrusted guest response, receipt, and telemetry
//! evidence carried by [`vsock`].

pub mod audit;
pub mod gate;

pub use audit::{
    AuditSink, AuditSinkError, BudgetDecision, DispatchDecision, HostOutcome, HostOutcomeRecord,
    InMemoryAuditSink, IntentAuditRecord, NewIntentRecord,
};
pub use gate::{GateDecision, HumanGate, LkmParamGate};

pub use vsock as transport;
