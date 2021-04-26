use algebra::serialize::*;

/// Defines common interfaces useful to serialize/deserialize structs.
pub trait SerializationUtils: CanonicalSerialize + CanonicalDeserialize {

    /// Returns the serialized byte size of `self`.
    fn get_size(&self) -> usize {
        self.serialized_size()
    }

    /// Serialize `self` to a byte array, returning a `SerializationError` if the operation fails.
    fn as_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buffer = Vec::with_capacity(self.get_size());
        CanonicalSerialize::serialize(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Attempts to deserialize a Self instance from `bytes`, returning a `SerializationError`
    /// if the operation fails.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        CanonicalDeserialize::deserialize(bytes)
    }
}

// Various impls
use crate::type_mapping::{FieldElement, GingerMHTPath, ScalarFieldElement, Affine, Projective};

impl SerializationUtils for FieldElement {}
impl SerializationUtils for GingerMHTPath {}
impl SerializationUtils for ScalarFieldElement {}
impl SerializationUtils for Affine {}
impl SerializationUtils for Projective {}