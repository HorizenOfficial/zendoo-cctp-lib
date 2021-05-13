use crate::{
    type_mapping::*,
    proving_system::error::ProvingSystemError,
    proving_system::{ZendooProof, ZendooVerifierKey, check_matching_proving_system_type},
};
use rand::RngCore;
use crate::proving_system::init::{get_g1_committer_key, get_g2_committer_key};

pub mod certificate;
pub mod ceased_sidechain_withdrawal;
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

    let ck_g1 = get_g1_committer_key()?;

    // Verify proof (selecting the proper proving system)
    let res = match (proof, vk) {

        // Verify CoboundaryMarlinProof
        (ZendooProof::CoboundaryMarlin(proof), ZendooVerifierKey::CoboundaryMarlin(vk)) =>
            CoboundaryMarlin::verify(
                vk,
                ck_g1.as_ref().unwrap(),
                usr_ins.as_slice(),
                &proof.0
            ).map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?,

        // Verify DarlinProof
        (ZendooProof::Darlin(proof), ZendooVerifierKey::Darlin(vk)) => {
            let ck_g2 = get_g2_committer_key()?;
            Darlin::verify(
                vk,
                ck_g1.as_ref().unwrap(),
                ck_g2.as_ref().unwrap(),
                usr_ins.as_slice(),
                proof,
                rng.unwrap()
            ).map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?
        },
        _ => unreachable!()
    };

    Ok(res)
}