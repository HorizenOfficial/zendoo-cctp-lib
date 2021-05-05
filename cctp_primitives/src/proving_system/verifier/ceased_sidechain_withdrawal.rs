use crate::proving_system::verifier::{ZendooVerifier, UserInputs};
use crate::type_mapping::{FieldElement, FIELD_SIZE};

pub struct CSWProofUserInputs<'a> {
    _amount:         u64,
    _sc_id:          &'a [u8; 32],
    _nullifier:      &'a [u8; FIELD_SIZE],
    _pub_key_hash:   &'a [u8; MC_PK_SIZE],
    _reedem_script:  &'a [u8],
    _cert_data_hash: &'a [u8; FIELD_SIZE],
}

impl UserInputs for CSWProofUserInputs {
    fn get_circuit_inputs(&self) -> Vec<FieldElement> { unimplemented!() }
}

pub struct ZendooCSWProofVerifier<'a>(PhantomData<&'a ()>);

impl<'a> ZendooVerifier for ZendooCSWProofVerifier<'a> {
    type Inputs = CSWProofUserInputs<'a>;
}