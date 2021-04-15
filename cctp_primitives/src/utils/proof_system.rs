use algebra::Field;
use r1cs_core::ConstraintSynthesizer;
use crate::{
    type_mapping::{
        FieldElement, Error, GingerMHT,
    },
    utils::serialization::SerializationUtils,
};
use primitives::merkle_tree::field_based_mht::{
    FieldBasedMerkleTree,
    tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS
};
use rand::RngCore;

/// Defines common interfaces for calling the prover/verifier of a given proving system
pub trait ProvingSystemUtils<F: Field> {
    type Proof: SerializationUtils;
    type ProverKey: SerializationUtils;
    type VerifierKey: SerializationUtils;

    /// Create the proving key and verification key, for the implementer's proving system,
    /// for a specific R1CS circuit `circuit`.
    fn setup<C: ConstraintSynthesizer<F>>(circuit: C) -> Result<(Self::ProverKey, Self::VerifierKey), Error>;

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

const BT_MERKLE_TREE_HEIGHT: usize = 12;

pub fn get_bt_merkle_root(bt_list: Vec<FieldElement>) -> Result<FieldElement, Error>
{
    if bt_list.len() > 0 {
        let mut bt_mt =
            GingerMHT::init(BT_MERKLE_TREE_HEIGHT, 2usize.pow(BT_MERKLE_TREE_HEIGHT as u32));
        for fe in bt_list.into_iter(){
            bt_mt.append(fe);
        }
        bt_mt.finalize_in_place();
        bt_mt.root().ok_or(Error::from("Failed to compute BT Merkle Tree root"))

    } else {
        // TODO: Replace with Tweedle Phantom Merkle Root
        Ok(TWEEDLE_MHT_POSEIDON_PARAMETERS.nodes[BT_MERKLE_TREE_HEIGHT])
    }
}