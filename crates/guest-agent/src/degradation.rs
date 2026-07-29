/// Explicit evidence that a procfs projection used a degraded input or fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcDegradation {
    pub path: String,
    pub reason: String,
}

impl ProcDegradation {
    pub fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}
