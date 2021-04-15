use algebra::SerializationError;
use crate::{
    type_mapping::*,
    proving_system::error::ProvingSystemError,
    utils::{
        serialization::SerializationUtils,
        proof_system::ProvingSystemUtils,
    },
};
use rand::RngCore;

pub mod certificate;
// To be defined
//pub mod ceased_sidechain_withdrawal;
pub mod batch_verifier;

/// Utility enum, allowing the cryptolibs to pass data and
/// specify the proving system type at the same type.
#[derive(Clone)]
pub enum RawVerifierData {
    CoboundaryMarlin{ proof: Vec<u8>, vk: Vec<u8> },
    Darlin{ proof: Vec<u8>, vk: Vec<u8> }
}

/// Enum containing all that is needed to perform the batch verification,
/// separated by proving system type. It is the deserialized version of
/// `RawVerifierData` plus the public inputs needed to verify the proof
#[derive(Clone)]
pub enum VerifierData {
    CoboundaryMarlin(CoboundaryMarlinProof, CoboundaryMarlinVerifierKey, Vec<FieldElement>),
    Darlin(DarlinProof, DarlinVerifierKey, Vec<FieldElement>),
}

impl VerifierData {
    /// Deserialize the content of `RawVerifierData` to get a Self instance
    /// (adding also the `usr_ins`)
    pub(crate) fn from_raw(
        raw: RawVerifierData,
        usr_ins: Vec<FieldElement>
    ) -> Result<Self, SerializationError>
    {
        match raw {
            RawVerifierData::CoboundaryMarlin { proof, vk } => {
                let proof = CoboundaryMarlinProof::from_bytes(&proof)?;
                let vk = CoboundaryMarlinVerifierKey::from_bytes(&vk)?;
                Ok(VerifierData::CoboundaryMarlin(proof, vk, usr_ins))
            },
            RawVerifierData::Darlin { proof, vk } => {
                let proof = DarlinProof::from_bytes(&proof)?;
                let vk = DarlinVerifierKey::from_bytes(&vk)?;
                Ok(VerifierData::Darlin(proof, vk, usr_ins))
            },
        }
    }

    /// Verify the content of `self`
    pub fn verify<R: RngCore>(
        self,
        rng: Option<&mut R>
    ) -> Result<bool, ProvingSystemError>
    {
        // Verify proof (selecting the proper proving system)
        let res = match self {
            VerifierData::CoboundaryMarlin(proof, vk, usr_ins) =>
                CoboundaryMarlin::verify_proof(&proof, &vk, usr_ins, rng)
                    .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?,
            VerifierData::Darlin(proof, vk, usr_ins) =>
                Darlin::verify_proof(&proof, &vk, usr_ins, rng)
                    .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?,
        };

        Ok(res)
    }
}

/// Wrapper for the user inputs of a circuit, assumed to be a vector of Field Elements
pub trait UserInputs {
    /// Handle all the boiler plate to get the user inputs of a given circuit.
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError>;
}

/// Interface for a verifier of Zendoo circuits, generic with respect to the user inputs
/// of the circuit and the proving system.
pub trait ZendooVerifier {
    type Inputs: UserInputs;

    fn verify_proof<R: RngCore>(
        inputs:       &Self::Inputs,
        proof_and_vk: RawVerifierData,
        rng:          Option<&mut R>,
    ) -> Result<bool, ProvingSystemError>
    {
        let usr_ins = inputs.get_circuit_inputs()?;
        let verifier_data = VerifierData::from_raw(proof_and_vk, usr_ins)
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;
        verifier_data.verify(rng)
    }
}