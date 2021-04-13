use algebra::Field;
use r1cs_core::ConstraintSynthesizer;
use crate::{
    type_mapping::Error, SerializationUtils
};
use rand::RngCore;

pub mod init;
pub mod coboundary_marlin;
pub mod final_darlin;
pub mod batch;

/// Defines common interfaces for calling the prover/verifier of a given proving system
pub trait ProvingSystemUtils<F: Field> {
    type Proof: SerializationUtils;
    type ProverKey: SerializationUtils;
    type VerifierKey: SerializationUtils;

    /// Create a proof for the implementer's proving system, given a R1CS circuit `circuit`
    /// and the corresponding prover key `pk`. If `zk` is requested, then `zk_rng` must be
    /// a cryptographically secure RNG, otherwise nothing.
    fn create_proof<C: ConstraintSynthesizer<F>>(
        circuit: C,
        pk: &Self::ProverKey,
        zk: bool,
        zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, Error>;

    /// Verify a proof for the implementer's proving system, given the proof `proof`, the
    /// corresponding verifier key `vk`, and the `public_inputs` against which the proof
    /// shall be verified. Some proving systems may require a cryptographically secure RNG
    /// in the verification process too, in which case it must be specified.
    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<F>,
        rng: Option<&mut R>,
    ) -> Result<bool, Error>;
}