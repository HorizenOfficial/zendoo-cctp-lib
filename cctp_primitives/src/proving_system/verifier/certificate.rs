use crate::{
    type_mapping::{FIELD_SIZE, FieldElement, FieldHash},
    proving_system::{
        verifier::{UserInputs, ZendooVerifier},
        error::ProvingSystemError,
    },
    utils::serialization::SerializationUtils
};
use primitives::FieldBasedHash;
use crate::utils::get_wcert_sysdata_hash;

/// All the data needed to reconstruct the aggregated input for the NaiveThresholdSignatureCircuit
/// included in the Certificate.
pub struct CertificateProofUserInputs<'a> {
    curr_cumulative_sc_tx_comm_tree_root: &'a [u8; FIELD_SIZE],
    custom_fields:                        &'a [[u8; FIELD_SIZE]],
    epoch_number:                         u32,
    bt_list:                              &'a [(u64,[u8; 20])],
    quality:                              u64,
    constant:                             &'a [u8; FIELD_SIZE],
}

impl UserInputs for CertificateProofUserInputs<'_> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {

        let wcert_sysdata_hash = get_wcert_sysdata_hash(
            self.curr_cumulative_sc_tx_comm_tree_root, self.custom_fields,
            self.epoch_number, self.bt_list, self.quality
        ).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        // Compute aggregated input
        let aggregated_input = {
            let mut digest = FieldHash::init_constant_length(2, None);
            digest
                .update(
                FieldElement::from_bytes(self.constant)
                    .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
                )
                .update(wcert_sysdata_hash)
                .finalize()
                .unwrap()
        };

        Ok(vec![aggregated_input])
    }
}

pub struct ZendooCertProofVerifier<'a>(std::marker::PhantomData<&'a ()>);

impl<'a> ZendooVerifier for ZendooCertProofVerifier<'a> {
    type Inputs = CertificateProofUserInputs<'a>;
}