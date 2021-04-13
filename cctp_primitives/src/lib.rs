#![deny(
unused_import_braces,
unused_qualifications,
trivial_casts,
trivial_numeric_casts
)]
#![deny(
unused_qualifications,
variant_size_differences,
stable_features,
unreachable_pub
)]
#![deny(
non_shorthand_field_patterns,
unused_attributes,
unused_imports,
unused_extern_crates
)]
#![deny(
renamed_and_removed_lints,
stable_features,
unused_allocation,
unused_comparisons,
bare_trait_objects
)]
#![deny(
const_err,
unused_must_use,
unused_mut,
unused_unsafe,
private_in_public,
unsafe_code
)]
#![forbid(unsafe_code)]

pub mod type_mapping;
pub use self::type_mapping::*;

pub mod commitment_tree;
pub mod bit_vector;
pub mod utils;
pub mod proof_system;

use algebra::serialize::*;

/// Defines common interfaces useful to serialize/deserialize structs.
pub trait SerializationUtils: CanonicalSerialize + CanonicalDeserialize {

    /// Returns the serialized byte size of `self`.
    fn get_size(&self) -> usize {
        self.serialized_size()
    }

    /// Serialize `self` to a byte array, returning a `SerializationError` if the operation fails.
    fn to_byte_vec(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buffer = vec![0u8; self.get_size()];
        CanonicalSerialize::serialize(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Attempts to deserialize a Self instance from `bytes`, returning a `SerializationError`
    /// if the operation fails.
    fn from_byte_vec(bytes: Vec<u8>) -> Result<Self, SerializationError> {
        CanonicalDeserialize::deserialize(bytes.as_slice())
    }
}
