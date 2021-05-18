use algebra::field_new;
use crate::proving_system::{
    verifier::UserInputs, error::ProvingSystemError,
};
use crate::type_mapping::{FieldElement, BigInteger256, MC_PK_SIZE};
use crate::utils::commitment_tree::{ByteAccumulator, hash_vec};

pub const PHANTOM_CERT_DATA_HASH: FieldElement =
    field_new!(FieldElement, BigInteger256([
        2469563128534465273,
        17026353330366205828,
        18445727066182202834,
        4611686018427387903
    ])
);

pub struct CSWProofUserInputs<'a> {
    pub amount:                                     u64,
    pub sc_id:                                      &'a FieldElement,
    pub pub_key_hash:                               &'a [u8; MC_PK_SIZE],
    pub cert_data_hash:                             &'a FieldElement,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a FieldElement,
}

impl<'a> UserInputs for CSWProofUserInputs<'a> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {

        let mut fes = ByteAccumulator::init()
            .update(self.amount).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            .update(&self.pub_key_hash[..]).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            .get_field_elements().map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        fes.append(&mut vec![
            *self.sc_id, *self.cert_data_hash, *self.end_cumulative_sc_tx_commitment_tree_root
        ]);

        Ok(vec![hash_vec(fes).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?])
    }
}

#[cfg(test)]
#[test]
fn test_phantom_cert_data_hash() {
    assert_eq!(
        PHANTOM_CERT_DATA_HASH,
        ByteAccumulator::init()
            .update(&b"BASOOKA"[..]).unwrap()
            .get_field_elements().unwrap()[0]
    );
}