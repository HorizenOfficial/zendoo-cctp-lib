use primitives::{FieldBasedHash, FieldBasedMerkleTree};
use crate::type_mapping::{FieldElement, FieldHash, GingerMHT, GingerMHTPath};
use rand::Rng;
use algebra::{ToBytes, FromBytes};
use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt, LittleEndian, WriteBytesExt};

pub type Error = Box<dyn std::error::Error>;

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

// Calculates hash of a sequentially concatenated data elements of fixed size.
pub fn hash_vec_constant_length(data: &Vec<FieldElement>, length: usize) -> Result<FieldElement, Error> {
    let mut hasher = <FieldHash>::init_constant_length(length, None);
    for &fe in data {
        hasher.update(fe);
    }
    hasher.finalize()
}

// Calculates hash of a sequentially concatenated data elements of variable size.
pub fn hash_vec_variable_length(data: &Vec<FieldElement>, mod_rate: bool) -> Result<FieldElement, Error> {
    let mut hasher = <FieldHash>::init_variable_length(mod_rate, None);
    for &fe in data {
        hasher.update(fe);
    }
    hasher.finalize()
}


// Generates vector of random bytes
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


// Serializes GingerMHTPath into a byte-array
pub fn mpath_to_bytes(mpath: &GingerMHTPath) -> Vec<u8>{
    let mut bytes = Vec::new();
    mpath.write(&mut bytes).unwrap();
    bytes
}

// Returns GingerMHTPath corresponding to the given bytes
// NOTE: The given byte-array should be a serialized GingerMHTPath
pub fn mpath_from_bytes(bytes: &[u8]) -> Result<GingerMHTPath, Error>{
    if let Ok(mpath) = GingerMHTPath::read(bytes){
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