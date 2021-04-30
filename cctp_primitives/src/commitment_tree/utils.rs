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
    _get_root_from_field_vec(bytes_to_field_elements(bt_list.to_vec())?, 12)
}

//--------------------------------------------------------------------------------------------------
// Hash utils
//--------------------------------------------------------------------------------------------------

// Calculates hash of a sequentially concatenated data elements
pub fn hash_vec(data: Vec<FieldElement>) -> FieldElement {
    let mut hasher = FieldHash::init(None);
    data.into_iter().for_each(|fe| { hasher.update(fe); });
    hasher.finalize()
}

// Computes FieldElement-based hash on the given byte-array
pub fn hash_bytes(bytes: Vec<u8>) -> Result<FieldElement, Error> {
    Ok(hash_vec(bytes_to_field_elements(bytes)?))
}

// Converts byte-array into a sequence of FieldElements
pub fn bytes_to_field_elements<T: ToBytes>(bytes: Vec<T>) -> Result<Vec<FieldElement>, Error> {
    let mut bits = primitives::bytes_to_bits(&to_bytes!(bytes)?);
    // byte serialization is in little endian, but bit serialization is in big endian: we need to reverse.
    bits.reverse();
    bits.to_field_elements()
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