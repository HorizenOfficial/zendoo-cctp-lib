use crate::{
    type_mapping::{
        CoboundaryMarlin, CoboundaryMarlinProverKey, CoboundaryMarlinVerifierKey, CoboundaryMarlinProof,
        FieldElement, Error
    },
    proof_system::{ProvingSystemUtils, init::G1_COMMITTER_KEY},
    SerializationUtils
};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;

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