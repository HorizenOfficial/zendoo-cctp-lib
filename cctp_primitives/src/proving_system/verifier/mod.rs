use crate::{
    type_mapping::*,
    proving_system::error::ProvingSystemError,
    utils::proving_system::ProvingSystemUtils,
};
use rand::RngCore;

pub mod certificate;
// To be defined
//pub mod ceased_sidechain_withdrawal;
pub mod batch_verifier;

/// Wrapper for the user inputs of a circuit, assumed to be a vector of Field Elements
pub trait UserInputs {
    /// Handle all the boiler plate to get the user inputs of a given circuit.
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError>;
}

/// Enum containing all that is needed to perform the batch verification,
/// separated by proving system type.
#[derive(Clone)]
pub enum VerifierData {
    CoboundaryMarlin(CoboundaryMarlinProof, CoboundaryMarlinVerifierKey),
    Darlin(DarlinProof, DarlinVerifierKey),
}

impl VerifierData {
    /// Verify the content of `self`
    pub fn verify<I: UserInputs, R: RngCore>(
        &self,
        inputs: I,
        rng: Option<&mut R>
    ) -> Result<bool, ProvingSystemError>
    {
        let usr_ins = inputs.get_circuit_inputs()?;

        // Verify proof (selecting the proper proving system)
        let res = match self {
            VerifierData::CoboundaryMarlin(proof, vk) =>
                CoboundaryMarlin::verify_proof(&proof, &vk, usr_ins, rng)
                    .map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?,
            VerifierData::Darlin(proof, vk) =>
                Darlin::verify_proof(&proof, &vk, usr_ins, rng)
                    .map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?,
        };

        Ok(res)
    }
}