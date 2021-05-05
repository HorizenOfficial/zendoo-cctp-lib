pub mod init;
pub mod verifier;
pub mod error;

use crate::{
    type_mapping::{
        CoboundaryMarlin, CoboundaryMarlinProverKey, CoboundaryMarlinVerifierKey, CoboundaryMarlinProof,
        Darlin, DarlinProverKey, DarlinVerifierKey, DarlinProof,
        FieldElement,
    },
    proving_system::{
        init::{
            get_g1_committer_key, get_g2_committer_key,
        },
        error::ProvingSystemError,
    },
    utils::proof_system::ProvingSystemUtils,
};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;
use proof_systems::darlin::pcd::simple_marlin::MarlinProof;

// *************************COBOUNDARY MARLIN********************************

impl ProvingSystemUtils<FieldElement> for CoboundaryMarlin {
    type Proof = CoboundaryMarlinProof;
    type ProverKey = CoboundaryMarlinProverKey;
    type VerifierKey = CoboundaryMarlinVerifierKey;

    fn setup<C: ConstraintSynthesizer<FieldElement>>(
        circuit: C
    ) -> Result<(Self::ProverKey, Self::VerifierKey), ProvingSystemError>
    {
        let ck = get_g1_committer_key()?;

        let (pk, vk) = CoboundaryMarlin::index(ck.as_ref().unwrap(), circuit)
            .map_err(|e| ProvingSystemError::SetupFailed(format!("{:?}", e)))?;
        Ok((pk, vk))
    }

    fn create_proof<C: ConstraintSynthesizer<FieldElement>>(
        circuit: C,
        pk: &Self::ProverKey,
        zk: bool,
        zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, ProvingSystemError>
    {
        let ck = get_g1_committer_key()?;

        let proof = CoboundaryMarlin::prove(
            pk, ck.as_ref().unwrap(),
            circuit, zk, zk_rng
        ).map_err(|e| ProvingSystemError::ProofCreationFailed(format!("{:?}", e)))?;

        Ok(MarlinProof(proof))
    }

    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<FieldElement>,
        _rng: Option<&mut R>,
    ) -> Result<bool, ProvingSystemError> {

        let ck = get_g1_committer_key()?;

        let result = CoboundaryMarlin::verify(
            vk, ck.as_ref().unwrap(),
            public_inputs.as_slice(), proof
        ).map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?;

        Ok(result)
    }
}

// *************************(FINAL) DARLIN********************************

impl ProvingSystemUtils<FieldElement> for Darlin<'_> {
    type Proof = DarlinProof;
    type ProverKey = DarlinProverKey;
    type VerifierKey = DarlinVerifierKey;

    /// We still don't have recursion, therefore we are not able to create Darlin proving key and verification key.
    fn setup<C: ConstraintSynthesizer<FieldElement>>(
        _circuit: C
    ) -> Result<(Self::ProverKey, Self::VerifierKey), ProvingSystemError>
    { unimplemented!() }

    /// We still don't have recursion, therefore we are not able to create Darlin proofs
    fn create_proof<C: ConstraintSynthesizer<FieldElement>>(
        _circuit: C,
        _pk: &Self::ProverKey,
        _zk: bool,
        _zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, ProvingSystemError>
    { unimplemented!() }

    /// The verification process given a FinalDarlinProof, instead, it's clear
    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<FieldElement>,
        rng: Option<&mut R>,
    ) -> Result<bool, ProvingSystemError>
    {
        let ck_g1 = get_g1_committer_key()?;
        let ck_g2 = get_g2_committer_key()?;

        let rng = rng.unwrap();

        let result = Darlin::verify(
            vk, ck_g1.as_ref().unwrap(), ck_g2.as_ref().unwrap(),
            public_inputs.as_slice(), proof, rng
        ).map_err(|e| ProvingSystemError::ProofVerificationFailed(format!("{:?}", e)))?;

        Ok(result)
    }
}