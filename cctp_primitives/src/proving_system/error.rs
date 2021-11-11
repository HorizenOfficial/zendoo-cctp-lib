use std::{
    error::Error,
    fmt::{Debug, Display},
};

#[derive(Debug)]
pub enum ProvingSystemError {
    UndefinedProvingSystem,
    ProvingSystemMismatch,
    CommitterKeyNotInitialized,
    SetupFailed(String),
    ProofCreationFailed(String),
    ProofVerificationFailed(String),
    FailedBatchVerification(Option<Vec<u32>>),
    NoProofsToVerify,
    ProofAlreadyExists(u32),
    ProofNotPresent(u32),
    Other(String),
}

impl Display for ProvingSystemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProvingSystemError::UndefinedProvingSystem => {
                write!(f, "A valid proving system type must be specified !")
            }
            ProvingSystemError::ProvingSystemMismatch => write!(
                f,
                "Not all of the crypto artifacts belong to the same proving system"
            ),
            ProvingSystemError::CommitterKeyNotInitialized => {
                write!(f, "Committer Key has not been loaded")
            }
            ProvingSystemError::SetupFailed(err) => {
                write!(f, "Failed to generate pk and vk {}", err)
            }
            ProvingSystemError::ProofCreationFailed(err) => {
                write!(f, "Failed to create proof {}", err)
            }
            ProvingSystemError::ProofVerificationFailed(err) => {
                write!(f, "Failed to verify proof {}", err)
            }
            ProvingSystemError::FailedBatchVerification(maybe_ids) => match maybe_ids {
                Some(ids) => write!(
                    f,
                    "Batch verification failed due to proofs with ids: {:?}",
                    ids
                ),
                None => write!(
                    f,
                    "Batch verification failed. Unable to determine the offending proofs"
                ),
            },
            ProvingSystemError::NoProofsToVerify => write!(f, "There is no proof to verify"),
            ProvingSystemError::ProofAlreadyExists(id) => write!(
                f,
                "Proof with id: {} has already been added to the batch",
                id
            ),
            ProvingSystemError::ProofNotPresent(id) => {
                write!(f, "Proof with id: {} is not present in the batch", id)
            }
            ProvingSystemError::Other(err) => write!(f, "{}", err),
        }
    }
}

impl Error for ProvingSystemError {}
