/// Keystore Error Type.
#[derive(Debug, thiserror::Error)]
pub enum LairError {
    /// An error generated from the GhostActor system.
    #[error("LairError: {0}")]
    GhostError(#[from] ghost_actor::GhostError),

    /// Trying to start up Lair process, but a pidfile/process already exists
    #[error("Lair pidfile/process already exists")]
    ProcessAlreadyExists,

    /// Unspecified Internal error.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl LairError {
    /// Build an "Other" type LairError.
    pub fn other(
        e: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        LairError::Other(e.into())
    }
}

impl From<String> for LairError {
    fn from(s: String) -> Self {
        #[derive(Debug, thiserror::Error)]
        struct OtherError(String);
        impl std::fmt::Display for OtherError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        LairError::other(OtherError(s))
    }
}

impl From<&str> for LairError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<LairError> for () {
    fn from(_: LairError) {}
}

/// Lair Result Type.
pub type LairResult<T> = Result<T, LairError>;
