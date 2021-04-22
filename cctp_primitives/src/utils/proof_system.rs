use algebra::Field;
use crate::{
    proving_system::error::ProvingSystemError,
    utils::serialization::SerializationUtils
};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;

/// Defines common interfaces for calling the prover/verifier of a given proving system
pub trait ProvingSystemUtils<F: Field> {
    type Proof: SerializationUtils;
    type ProverKey: SerializationUtils;
    type VerifierKey: SerializationUtils;

    /// Create the proving key and verification key, for the implementer's proving system,
    /// for a specific R1CS circuit `circuit`.
    fn setup<C: ConstraintSynthesizer<F>>(
        circuit: C
    ) -> Result<(Self::ProverKey, Self::VerifierKey), ProvingSystemError>;

    /// Create a proof for the implementer's proving system, given a R1CS circuit `circuit`
    /// and the corresponding prover key `pk`. If `zk` is requested, then `zk_rng` must be
    /// a cryptographically secure RNG, otherwise nothing.
    fn create_proof<C: ConstraintSynthesizer<F>>(
        circuit: C,
        pk: &Self::ProverKey,
        zk: bool,
        zk_rng: Option<&mut dyn RngCore>
    ) -> Result<Self::Proof, ProvingSystemError>;

    /// Verify a proof for the implementer's proving system, given the proof `proof`, the
    /// corresponding verifier key `vk`, and the `public_inputs` against which the proof
    /// shall be verified. Some proving systems may require a cryptographically secure RNG
    /// in the verification process too, in which case it must be specified.
    fn verify_proof<R: RngCore>(
        proof: &Self::Proof,
        vk: &Self::VerifierKey,
        public_inputs: Vec<F>,
        rng: Option<&mut R>,
    ) -> Result<bool, ProvingSystemError>;
}