//! PoseidonHash wrappers, used by cryptolibs.

use crate::type_mapping::{Error, FieldElement, FieldHash};
use primitives::FieldBasedHash;

pub fn get_poseidon_hash_constant_length(
    input_size: usize,
    personalization: Option<Vec<&FieldElement>>,
) -> FieldHash {
    if let Some(personalization) = personalization {
        FieldHash::init_constant_length(
            input_size,
            Some(
                personalization
                    .into_iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        )
    } else {
        FieldHash::init_constant_length(input_size, None)
    }
}

pub fn get_poseidon_hash_variable_length(
    mod_rate: bool,
    personalization: Option<Vec<&FieldElement>>,
) -> FieldHash {
    if let Some(personalization) = personalization {
        FieldHash::init_variable_length(
            mod_rate,
            Some(
                personalization
                    .into_iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        )
    } else {
        FieldHash::init_variable_length(mod_rate, None)
    }
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement) {
    hash.update(*input);
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<Vec<&FieldElement>>) {
    if let Some(personalization) = personalization {
        hash.reset(Some(
            personalization
                .into_iter()
                .copied()
                .collect::<Vec<_>>()
                .as_slice(),
        ))
    } else {
        hash.reset(None)
    };
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> Result<FieldElement, Error> {
    let result = hash.finalize()?;
    Ok(result)
}
