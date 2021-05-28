use crate::{
    type_mapping::FieldElement,
    proving_system::{
        verifier::UserInputs,
        error::ProvingSystemError,
    },
};
use crate::utils::get_cert_data_hash;
use crate::utils::data_structures::BackwardTransfer;

/// All the data needed to reconstruct the aggregated input for the NaiveThresholdSignatureCircuit
/// included in the Certificate.
#[derive(Clone)]
pub struct CertificateProofUserInputs<'a> {
    pub constant:                                   Option<&'a FieldElement>,
    pub epoch_number:                               u32,
    pub quality:                                    u64,
    pub bt_list:                                    Option<&'a [BackwardTransfer]>,
    pub custom_fields:                              Option<Vec<&'a FieldElement>>,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a FieldElement,
    pub btr_fee:                                    u64,
    pub ft_min_amount:                              u64
}

impl UserInputs for CertificateProofUserInputs<'_> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        let mut inputs = Vec::new();

        if self.constant.is_some() {
            inputs.push(*self.constant.unwrap());
        }

        let cert_data_hash = get_cert_data_hash(
            self.epoch_number, self.quality, self.bt_list, self.custom_fields.clone(),
            self.end_cumulative_sc_tx_commitment_tree_root, self.btr_fee, self.ft_min_amount
        ).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;
        inputs.push(cert_data_hash);

        Ok(inputs)
    }
}