use crate::proving_system::{
    verifier::UserInputs, error::ProvingSystemError,
};
use crate::type_mapping::{FieldElement, MC_PK_SIZE};

pub struct CSWProofUserInputs<'a> {
    pub amount:                                     u64,
    pub sc_id:                                      &'a [u8; 32],
    pub pub_key_hash:                               &'a [u8; MC_PK_SIZE],
    pub cert_data_hash:                             &'a FieldElement,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a FieldElement,
}

impl<'a> UserInputs for CSWProofUserInputs<'a> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> { unimplemented!() }
}