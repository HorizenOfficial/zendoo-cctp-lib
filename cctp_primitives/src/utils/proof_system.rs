use algebra::{serialize::*, Field};
use crate::{
    type_mapping::{FieldElement, ProvingSystem, CoboundaryMarlin, Darlin, Error},
    proving_system::{
        init::{load_g1_committer_key, load_g2_committer_key},
        error::ProvingSystemError,
    },
    utils::serialization::write_to_file,
};
use r1cs_core::ConstraintSynthesizer;
use rand::RngCore;

/// Defines common interfaces for calling the prover/verifier of a given proving system
pub trait ProvingSystemUtils<F: Field> {
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    type ProverKey: CanonicalSerialize + CanonicalDeserialize;
    type VerifierKey: CanonicalSerialize + CanonicalDeserialize;

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

/// Utility function: initialize and save to specified paths the G1CommitterKey
/// and G2CommitterKey (iff ProvingSystem::Darlin).
pub fn init_dlog_keys(
    proving_system: ProvingSystem,
    segment_size: usize,
    ck_g1_path: &str,
    ck_g2_path: &str,
) -> Result<(), Error> {
    load_g1_committer_key(segment_size - 1, ck_g1_path)?;

    if matches!(proving_system, ProvingSystem::Darlin) {
        load_g2_committer_key(segment_size - 1, ck_g2_path)?
    }

    Ok(())
}

/// Utility function: generate and save to specified paths the SNARK proving and
/// verification key associated to circuit `circ`.
pub fn generate_circuit_keypair<C: ConstraintSynthesizer<FieldElement>>(
    circ: C,
    proving_system: ProvingSystem,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), Error>
{
    match proving_system {
        ProvingSystem::CoboundaryMarlin => {
            let (pk, vk) = CoboundaryMarlin::setup(circ)?;
            write_to_file(&pk, pk_path)?;
            write_to_file(&vk, vk_path)?;
        },
        ProvingSystem::Darlin => {
            let (pk, vk) = Darlin::setup(circ)?;
            write_to_file(&pk, pk_path)?;
            write_to_file(&vk, vk_path)?;
        }
    }

    Ok(())
}