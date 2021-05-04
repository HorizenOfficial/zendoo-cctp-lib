//! PoseidonHash wrappers, used by cryptolibs.

use crate::type_mapping::{FieldElement, FieldHash, Error};
use primitives::FieldBasedHash;

pub fn get_poseidon_hash_constant_length(input_size: usize, personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init_constant_length(input_size, personalization)
}

pub fn get_poseidon_hash_variable_length(mod_rate: bool, personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init_variable_length(mod_rate, personalization)
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement){
    hash.update(*input);
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<&[FieldElement]>){
    hash.reset(personalization);
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> Result<FieldElement, Error> {
    let result = hash.finalize()?;
    Ok(result)
}