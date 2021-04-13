use primitives::{FieldBasedHash, FieldBasedMerkleTree};
use crate::type_mapping::{FieldElement, FieldHash, GingerMHT, Error};
use rand::Rng;
use algebra::{ToBytes, FromBytes};

pub const fn pow2(power: usize) -> usize { 1 << power }

// Creates new FieldElement-based MT
pub fn new_mt(height: usize) -> Result<GingerMHT, Error> {
    let processing_step = 2usize.pow(height as u32);
    Ok(GingerMHT::init(
        height,
        processing_step
    ))
}

// Sequentially inserts leafs into an MT by using a specified position which is incremented afterwards
// Returns false if there is no more place to insert a leaf
pub fn add_leaf(tree: &mut GingerMHT, leaf: &FieldElement, pos: &mut usize, capacity: usize) -> bool {
    if *pos < capacity {
        tree.append(*leaf); *pos += 1;
        true
    } else {
        false
    }
}

// Calculates hash of a sequentially concatenated data elements
pub fn hash_vec(data: &Vec<FieldElement>) -> FieldElement {
    let mut hasher = <FieldHash>::init(None);
    for &fe in data {
        hasher.update(fe);
    }
    hasher.finalize()
}

// Generated vector of random bytes
pub fn rand_vec(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0.. len).map(|_|rng.gen()).collect()
}

// Serializes FieldElement into a byte-array
pub fn fe_to_bytes(fe: &FieldElement) -> Vec<u8>{
    let mut bytes = Vec::new();
    fe.write(&mut bytes).unwrap();
    bytes
}

// Returns FieldElement corresponding to the given bytes
// NOTE: The given byte-array should be a serialized FieldElement
pub fn fe_from_bytes(bytes: &[u8]) -> Result<FieldElement, Error>{
    if let Ok(fe) = FieldElement::read(bytes){
        Ok(fe)
    } else {
        Err("Couldn't parse the input bytes".into())
    }
}
