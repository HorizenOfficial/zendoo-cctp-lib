use primitives::{FieldBasedHash, FieldBasedMerkleTree};
use crate::commitment_tree::{FieldElement, FieldHash, FieldElementsMT, MerklePath};
use rand::Rng;
use algebra::{ToBytes, FromBytes};
use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt, LittleEndian, WriteBytesExt};

pub type Error = Box<dyn std::error::Error>;

pub const fn pow2(power: usize) -> usize { 1 << power }

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

//--------------------------------------------------------------------------------------------------
// Serialization utils
//--------------------------------------------------------------------------------------------------

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


// Serializes MerklePath into a byte-array
pub fn mpath_to_bytes(mpath: &MerklePath) -> Vec<u8>{
    let mut bytes = Vec::new();
    mpath.write(&mut bytes).unwrap();
    bytes
}

// Returns MerklePath corresponding to the given bytes
// NOTE: The given byte-array should be a serialized MerklePath
pub fn mpath_from_bytes(bytes: &[u8]) -> Result<MerklePath, Error>{
    if let Ok(mpath) = MerklePath::read(bytes){
        Ok(mpath)
    } else {
        Err("Couldn't parse the input bytes".into())
    }
}

// Reads chunk of specified size from the input stream
pub fn read_chunk(stream: &mut Cursor<&[u8]>, chunk_len: u32) -> Result<Vec<u8>, Error>{
    let mut chunk = vec![0u8; chunk_len as usize];
    stream.read_exact(&mut chunk)?;
    Ok(chunk)
}

// Reads LV-encoded value from the input stream
pub fn read_value(stream: &mut Cursor<&[u8]>) -> Result<Vec<u8>, Error>{
    let value_len = stream.read_u32::<LittleEndian>()?;
    if value_len != 0 {
        read_chunk(stream, value_len)
    } else {
        Err("Empty value".into())
    }
}

// Writes LV-encoded value to the output stream
pub fn write_value(stream: &mut Vec<u8>, value: &Vec<u8>){
    stream.write_u32::<LittleEndian>(value.len() as u32).unwrap();
    stream.extend(value)
}

// Writes empty value to the output stream
pub fn write_empty_value(stream: &mut Vec<u8>){
    write_value(stream, &vec![])
}