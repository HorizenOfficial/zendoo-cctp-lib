use crate::proving_system::{error::ProvingSystemError, verifier::UserInputs};
use crate::type_mapping::{BigInteger256, FieldElement, MC_PK_SIZE};
use crate::utils::commitment_tree::{hash_vec, DataAccumulator};
use algebra::field_new;

pub const PHANTOM_CERT_DATA_HASH: FieldElement = field_new!(
    FieldElement,
    BigInteger256([
        2469563128534465273,
        17026353330366205828,
        18445727066182202834,
        4611686018427387903
    ])
);

#[derive(Clone)]
pub struct CSWProofUserInputs<'a> {
    pub amount: u64,
    pub constant: Option<&'a FieldElement>,
    pub sc_id: &'a FieldElement,
    pub nullifier: &'a FieldElement,
    pub pub_key_hash: &'a [u8; MC_PK_SIZE],
    pub cert_data_hash: &'a FieldElement,
    pub end_cumulative_sc_tx_commitment_tree_root: &'a FieldElement,
}

impl<'a> UserInputs for CSWProofUserInputs<'a> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        let mut inputs = Vec::new();

        if self.constant.is_some() {
            inputs.push(*self.constant.unwrap());
        }

        let mut fes = DataAccumulator::init()
            .update(self.amount)
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            .update(&self.pub_key_hash[..])
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            .get_field_elements()
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        fes.append(&mut vec![
            *self.sc_id,
            *self.nullifier,
            *self.cert_data_hash,
            *self.end_cumulative_sc_tx_commitment_tree_root,
        ]);

        inputs.push(hash_vec(fes).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?);

        Ok(inputs)
    }
}

#[cfg(test)]
#[ignore]
#[test]
fn test_phantom_cert_data_hash() {
    assert_eq!(
        PHANTOM_CERT_DATA_HASH,
        DataAccumulator::init()
            .update(&b"BASOOKA"[..])
            .unwrap()
            .get_field_elements()
            .unwrap()[0]
    );
}
