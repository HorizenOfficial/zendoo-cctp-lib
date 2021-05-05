use std::{
    error::Error,
    fmt::{Display, Debug}
};

#[derive(Debug)]
pub enum ProvingSystemError {
    UndefinedProvingSystem,
    CommitterKeyNotInitialized,
    SetupFailed(String),
    ProofCreationFailed(String),
    ProofVerificationFailed(String),
    FailedBatchVerification(Option<String>),
    NoProofsToVerify,
    ProofAlreadyExists(String),
    ProofNotPresent(String),
    Other(String),
}

impl Display for ProvingSystemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProvingSystemError::UndefinedProvingSystem => write!(f, "A valid proving system type must be specified !"),
            ProvingSystemError::CommitterKeyNotInitialized => write!(f, "Committer Key has not been loaded"),
            ProvingSystemError::SetupFailed(err) => write!(f, "Failed to generate pk and vk {}", err),
            ProvingSystemError::ProofCreationFailed(err) => write!(f, "Failed to create proof {}", err),
            ProvingSystemError::ProofVerificationFailed(err) => write!(f, "Failed to verify proof {}", err),
            ProvingSystemError::FailedBatchVerification(maybe_id) => {
                match maybe_id {
                    Some(id) => write!(f, "Batch verification failed due to proof with id: {}", id),
                    None => write!(f, "Batch verification failed. Unable to determine the offending proof"),
                }
            },
            ProvingSystemError::NoProofsToVerify => write!(f, "There is no proof to verify"),
            ProvingSystemError::ProofAlreadyExists(id) => write!(
                f, "Proof with id: {} has already been added to the batch", id
            ),
            ProvingSystemError::ProofNotPresent(id) => write!(
                f, "Proof with id: {} is not present in the batch", id
            ),
            ProvingSystemError::Other(err) => write!(f, "{}", err)
        }
    }
}

impl Error for ProvingSystemError {}