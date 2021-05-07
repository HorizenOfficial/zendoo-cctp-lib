use primitives::FieldBasedHash;
use crate::type_mapping::{FIELD_SIZE, FieldElement, FieldHash, GingerMHT, Error};
use rand::Rng;
use algebra::{UniformRand, ToConstraintField, CanonicalSerialize};
use crate::utils::mht::{new_ginger_mht, append_leaf_to_ginger_mht};

pub const fn pow2(power: usize) -> usize { 1 << power }

//--------------------------------------------------------------------------------------------------
// Merkle Tree utils
//--------------------------------------------------------------------------------------------------

/// Creates new FieldElement-based MT
pub fn new_mt(height: usize) -> GingerMHT {
    new_ginger_mht(height, 2usize.pow(height as u32))
}

/// Sequentially inserts leafs into an MT by using a specified position which is incremented afterwards
/// Returns false if there is no more place to insert a leaf
pub fn add_leaf(tree: &mut GingerMHT, leaf: &FieldElement) -> bool {
    if append_leaf_to_ginger_mht(tree, leaf).is_ok() {
        true
    } else {
        false
    }
}

//--------------------------------------------------------------------------------------------------
// Hash utils
//--------------------------------------------------------------------------------------------------

/// Defaults to a constant length hash instance, given by data.len()
pub fn hash_vec(data: Vec<FieldElement>) -> Result<FieldElement, Error> {
    let length = data.len();
    hash_vec_constant_length(data, length)
}

/// Calculates hash of a sequentially concatenated data elements of fixed size.
pub fn hash_vec_constant_length(data: Vec<FieldElement>, length: usize) -> Result<FieldElement, Error> {
    let mut hasher = FieldHash::init_constant_length(length, None);
    data.into_iter().for_each(|fe| { hasher.update(fe); });
    hasher.finalize()
}

/// Calculates hash of a sequentially concatenated data elements of variable size.
pub fn hash_vec_variable_length(data: Vec<FieldElement>, mod_rate: bool) -> Result<FieldElement, Error> {
    let mut hasher = FieldHash::init_variable_length(mod_rate, None);
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
    pub fn update<T: CanonicalSerialize>(&mut self, serializable: T) -> Result<&mut Self, Error> {

        // Serialize serializable without saving any additional info
        let mut buffer = Vec::with_capacity(serializable.serialized_size());
        serializable.serialize_without_metadata(&mut buffer)?;

        let mut bits = primitives::bytes_to_bits(buffer.as_slice());
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
    pub fn compute_field_hash_constant_length(&self) -> Result<FieldElement, Error> {
        let fes = self.get_field_elements()?;
        hash_vec(fes)
    }

    /// (Safely) deserialize the accumulated bytes into FieldElements
    /// and then compute their FieldHash.
    pub fn compute_field_hash_variable_length(&self, mod_rate: bool) -> Result<FieldElement, Error> {
        let fes = self.get_field_elements()?;
        hash_vec_variable_length(fes, mod_rate)
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
    CanonicalSerialize::serialize(&FieldElement::rand(&mut rand::thread_rng()), &mut buffer[..]).unwrap();
    buffer
}

/// Generate random (but valid) array of field elements
pub fn rand_fe_vec(len: usize) -> Vec<[u8; FIELD_SIZE]> {
    (0..len).map(|_| rand_fe()).collect::<Vec<_>>()
}