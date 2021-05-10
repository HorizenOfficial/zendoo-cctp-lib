use primitives::{
    FieldBasedHash, FieldBasedMerkleTree,
    merkle_tree::field_based_mht::parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS
};
use crate::commitment_tree::{FieldElement, FieldHash, FieldElementsMT, FIELD_SIZE};
use rand::Rng;
use algebra::{to_bytes, ToBytes, UniformRand, ToConstraintField};

pub type Error = Box<dyn std::error::Error>;

pub const fn pow2(power: usize) -> usize { 1 << power }

//--------------------------------------------------------------------------------------------------
// Merkle Tree utils
//--------------------------------------------------------------------------------------------------

// Creates new FieldElement-based MT
pub fn new_mt(height: usize) -> Result<FieldElementsMT, Error> {
    let processing_step = 2usize.pow(height as u32);
    Ok(FieldElementsMT::init(
        height,
        processing_step
    ))
}

// Sequentially inserts leafs into an MT by using a specified position which is incremented afterwards
// Returns false if there is no more place to insert a leaf
pub fn add_leaf(tree: &mut FieldElementsMT, leaf: &FieldElement, pos: &mut usize, capacity: usize) -> bool {
    if *pos < capacity {
        tree.append(*leaf); *pos += 1;
        true
    } else {
        false
    }
}

fn _get_root_from_field_vec(field_vec: Vec<FieldElement>, height: usize) -> Result<FieldElement, Error> {
    assert!(height <= MHT_PARAMETERS.nodes.len());
    if field_vec.len() > 0 {
        let mut mt = new_mt(height)?;
        for fe in field_vec.into_iter(){
            mt.append(fe);
        }
        mt.finalize_in_place();
        mt.root().ok_or(Error::from("Failed to compute Merkle Tree root"))

    } else {
        Ok(MHT_PARAMETERS.nodes[height])
    }
}

/// Get the Merkle Root of a Binary Merkle Tree of height 12 built from the Backward Transfer list
pub fn get_bt_merkle_root(bt_list: &[(u64,[u8; 20])]) -> Result<FieldElement, Error>
{
    let mut leaves = Vec::with_capacity(bt_list.len());
    for bt in bt_list.iter() {
        let bt_fes = ByteAccumulator::init()
            .update(bt)?
            .get_field_elements()?;
        assert_eq!(bt_fes.len(), 1);
        leaves.push(bt_fes[0]);
    }
    _get_root_from_field_vec(leaves, 12)
}

//--------------------------------------------------------------------------------------------------
// Hash utils
//--------------------------------------------------------------------------------------------------

// Computes the hash of a vector of field elements
pub fn hash_vec(data: Vec<FieldElement>) -> FieldElement {
    let mut hasher = FieldHash::init(None);
    data.into_iter().for_each(|fe| { hasher.update(fe); });
    hasher.finalize()
}

/// Updatable struct that accumulates bytes into one or more FieldElements.
#[derive(Clone)]
pub struct ByteAccumulator {
    /// Each byte buffer is converted into bits: this allows to efficiently
    /// deserialize FieldElements out of them.
    bit_buffer: Vec<bool>
}

impl ByteAccumulator {
    /// Initialize an empty accumulator.
    pub fn init() -> Self { Self {bit_buffer: vec![] } }

    /// Update this struct with bytes obtained by serializing the input instance `serializable`.
    /// NOTE: Do not call if `serializable` is a FieldElement, since we enforce their explicit
    /// deserialization and we shall not use this accumulation strategy.
    /// In order to explicitly enforce this from this function we would need a negative trait
    /// bound for Field, but this feature is currently not supported by the language.
    pub fn update<T: ToBytes>(&mut self, serializable: T) -> Result<&mut Self, Error> {
        let mut bits = primitives::bytes_to_bits(&to_bytes!(serializable)?);
        // byte serialization is in little endian, but bit serialization is in big endian: we need to reverse.
        bits.reverse();
        self.bit_buffer.append(&mut bits);
        Ok(self)
    }

    /// (Safely) deserialize the accumulated bytes into FieldElements.
    pub fn get_field_elements(&self) -> Result<Vec<FieldElement>, Error> {
        self.bit_buffer.to_field_elements()
    }

    /// (Safely) deserialize the accumulated bytes into FieldElements
    /// and then compute their FieldHash.
    pub fn compute_field_hash(&self) -> Result<FieldElement, Error> {
        let fes = self.get_field_elements()?;
        Ok(hash_vec(fes))
    }
}

//--------------------------------------------------------------------------------------------------
// Serialization utils
//--------------------------------------------------------------------------------------------------

/// Generates vector of random bytes
pub fn rand_vec(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0.. len).map(|_|rng.gen()).collect()
}

/// Get random (but valid) field element
pub fn rand_fe() -> [u8; FIELD_SIZE]
{
    let mut buffer = [0u8; FIELD_SIZE];
    FieldElement::rand(&mut rand::thread_rng()).write(&mut buffer[..]).unwrap();
    buffer
}

/// Generate random (but valid) array of field elements
pub fn rand_fe_vec(len: usize) -> Vec<[u8; FIELD_SIZE]> {
    (0..len).map(|_| rand_fe()).collect::<Vec<_>>()
}