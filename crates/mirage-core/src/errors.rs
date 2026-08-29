use thiserror::Error;

pub const OPAQUE_MESSAGE: &str =
    "Authentication failed or archive is corrupted / not a valid Mirage archive.";

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MirageError {
    #[error("{0}")]
    Policy(String),

    #[error("{OPAQUE_MESSAGE}")]
    Opaque { internal: String },

    #[error("IO Error: {0}")]
    Io(String),
}

impl MirageError {
    pub fn opaque(internal: impl Into<String>) -> Self {
        Self::Opaque {
            internal: internal.into(),
        }
    }

    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    pub fn public_message(&self) -> String {
        match self {
            Self::Policy(msg) => msg.clone(),
            Self::Opaque { .. } => OPAQUE_MESSAGE.to_string(),
            Self::Io(_) => OPAQUE_MESSAGE.to_string(),
        }
    }

    pub fn internal_message(&self) -> &str {
        match self {
            Self::Policy(msg) => msg.as_str(),
            Self::Opaque { internal } => internal.as_str(),
            Self::Io(msg) => msg.as_str(),
        }
    }

    pub fn is_policy(&self) -> bool {
        matches!(self, Self::Policy(_))
    }

    pub fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque { .. })
    }
}

impl From<std::io::Error> for MirageError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
