use crypto_box as lib_crypto_box;

/// Keystore Error Type.
#[derive(Debug, thiserror::Error)]
pub enum LairError {
    /// An error generated from the GhostActor system.
    #[error("LairError: {0}")]
    GhostError(#[from] ghost_actor::GhostError),

    /// Trying to start up Lair process, but a pidfile/process already exists
    #[error("Lair pidfile/process already exists")]
    ProcessAlreadyExists,

    /// Failure to establish client connection to Lair IPC.
    #[error("IpcClientConnectError: {0} {1}")]
    IpcClientConnectError(String, Box<dyn std::error::Error + Send + Sync>),

    /// A public key was provided (e.g. for signing) that cannot be found in the keystore
    #[error("Public key not found")]
    PubKeyNotFound,

    /// Error during aead encryption, likely bad data.
    #[error("Aead error: {0}")]
    Aead(String),

    /// Error adding padding to encrypt data.
    #[error("Block pad error: {0}")]
    BlockPad(String),

    /// Error removing padding from decrypted data.
    #[error("Block unpad error: {0}")]
    BlockUnpad(String),

    /// Nonce byte lengths did not line up internally. Always very bad.
    #[error("CryptoBox nonce bad length")]
    CryptoBoxNonceLength,

    /// X25519 pub key lengths did not line up internally. Always very bad.
    #[error("X25519 pub key bad length")]
    X25519PubKeyLength,

    /// X25519 priv key lengths did not line up internally. Always very bad.
    #[error("X25519 priv key bad length")]
    X25519PrivKeyLength,

    /// A path to keypair was supposed to provided (e.g. KEY_DIR) cannot be found
    #[error("{0}")]
    DirError(String),
    
    /// Unspecified Internal error.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<lib_crypto_box::aead::Error> for LairError {
    fn from(aead_error: lib_crypto_box::aead::Error) -> Self {
        Self::Aead(aead_error.to_string())
    }
}

impl From<block_padding::PadError> for LairError {
    fn from(error: block_padding::PadError) -> Self {
        Self::BlockPad(format!("{:?}", error))
    }
}

impl From<block_padding::UnpadError> for LairError {
    fn from(error: block_padding::UnpadError) -> Self {
        Self::BlockUnpad(format!("{:?}", error))
    }
}

impl From<std::io::Error> for LairError {
    fn from(error: std::io::Error) -> Self {
        Self::DirError(error.to_string())
    }
}

impl From<serde_yaml::Error> for LairError {
    fn from(error: serde_yaml::Error) -> Self {
        Self::DirError(error.to_string())
    }
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
