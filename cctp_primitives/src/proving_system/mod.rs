pub mod init;
pub mod verifier;
pub mod error;

use crate::{
    type_mapping::{
        CoboundaryMarlin, CoboundaryMarlinProverKey, CoboundaryMarlinVerifierKey, CoboundaryMarlinProof,
        Darlin, DarlinProverKey, DarlinVerifierKey, DarlinProof,
        FieldElement, Error
    },
    proving_system::init::{G1_COMMITTER_KEY, G2_COMMITTER_KEY},
    utils::{
        serialization_utils::SerializationUtils,
        proof_system_utils::ProvingSystemUtils,
    },
};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;

// *************************COBOUNDARY MARLIN********************************

impl SerializationUtils for CoboundaryMarlinProof {}
impl SerializationUtils for CoboundaryMarlinProverKey {}
impl SerializationUtils for CoboundaryMarlinVerifierKey {}

impl ProvingSystemUtils<FieldElement> for CoboundaryMarlin {
    type Proof = CoboundaryMarlinProof;
    type ProverKey = CoboundaryMarlinProverKey;
    type VerifierKey = CoboundaryMarlinVerifierKey;

    fn create_proof<C: ConstraintSynthesizer<FieldElement>>(
        circuit: C,
        pk: &Self::ProverKey,
        zk: bool,
        zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, Error>
    {
        let ck = G1_COMMITTER_KEY.lock().unwrap();

        let proof = CoboundaryMarlin::prove(pk, &ck, circuit, zk, zk_rng)?;

        Ok(proof)
    }

    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<FieldElement>,
        _rng: Option<&mut R>,
    ) -> Result<bool, Error> {
        let ck = G1_COMMITTER_KEY.lock().unwrap();

        let result = CoboundaryMarlin::verify(vk, &ck, public_inputs.as_slice(), proof)?;

        Ok(result)
    }
}

// *************************(FINAL) DARLIN********************************
impl SerializationUtils for DarlinProof {}

impl ProvingSystemUtils<FieldElement> for Darlin<'_> {
    type Proof = DarlinProof;
    type ProverKey = DarlinProverKey;
    type VerifierKey = DarlinVerifierKey;

    /// We still don't have recursion, therefore we are not able to create Darlin proofs
    fn create_proof<C: ConstraintSynthesizer<FieldElement>>(
        _circuit: C,
        _pk: &Self::ProverKey,
        _zk: bool,
        _zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, Error>
    {
        unimplemented!()
    }

    /// The verification process given a FinalDarlinProof, instead, it's clear
    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<FieldElement>,
        rng: Option<&mut R>,
    ) -> Result<bool, Error>
    {
        let ck_g1 = G1_COMMITTER_KEY.lock().unwrap();
        let ck_g2 = G2_COMMITTER_KEY.lock().unwrap();

        let rng = rng.unwrap();

        let result = Darlin::verify(
            vk, &ck_g1, &ck_g2, public_inputs.as_slice(), proof, rng
        )?;

        Ok(result)
    }
}