use algebra::serialize::*;
use crate::type_mapping::FieldElement;


/// Defines common interfaces useful to serialize/deserialize structs.
pub trait SerializationUtils: CanonicalSerialize + CanonicalDeserialize {

    /// Returns the serialized byte size of `self`.
    fn get_size(&self) -> usize {
        self.serialized_size()
    }

    /// Serialize `self` to a byte array, returning a `SerializationError` if the operation fails.
    fn as_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buffer = vec![];
        CanonicalSerialize::serialize(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Attempts to deserialize a Self instance from `bytes`, returning a `SerializationError`
    /// if the operation fails.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        CanonicalDeserialize::deserialize(bytes)
    }
}

impl SerializationUtils for FieldElement {}