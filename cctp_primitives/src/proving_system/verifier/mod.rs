use crate::{
    type_mapping::*,
    proving_system::error::ProvingSystemError,
    utils::proving_system::ProvingSystemUtils,
};
use rand::RngCore;
use crate::utils::proving_system::{ZendooProof, ZendooVerifierKey, check_matching_proving_system_type};

pub mod certificate;
// To be defined
//pub mod ceased_sidechain_withdrawal;
pub mod batch_verifier;

/// Wrapper for the user inputs of a circuit, assumed to be a vector of Field Elements
pub trait UserInputs {
    /// Handle all the boiler plate to get the user inputs of a given circuit.
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError>;
}

/// Verify the content of `self`
pub fn verify_zendoo_proof<I: UserInputs, R: RngCore>(
    inputs: I,
    proof:  &ZendooProof,
    vk:     &ZendooVerifierKey,
    rng:    Option<&mut R>
) -> Result<bool, ProvingSystemError>
{
    let usr_ins = inputs.get_circuit_inputs()?;

    if !check_matching_proving_system_type(proof, vk) {
        return Err(ProvingSystemError::ProvingSystemMismatch);
    }

    // Verify proof (selecting the proper proving system)
    let res = match (proof, vk) {
        (ZendooProof::CoboundaryMarlin(proof), ZendooVerifierKey::CoboundaryMarlin(vk)) =>
            CoboundaryMarlin::verify_proof(proof, vk, usr_ins, rng)
                .map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?,
        (ZendooProof::Darlin(proof), ZendooVerifierKey::Darlin(vk)) =>
            Darlin::verify_proof(proof, vk, usr_ins, rng)
                .map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?,
        _ => unreachable!()
    };

    Ok(res)
}