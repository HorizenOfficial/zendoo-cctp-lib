use crate::{type_mapping::{FieldElement, Darlin, DarlinProof, DarlinProverKey, DarlinVerifierKey, Error}, proof_system::{ProvingSystemUtils, init::{G1_COMMITTER_KEY, G2_COMMITTER_KEY}}, SerializationUtils};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;

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