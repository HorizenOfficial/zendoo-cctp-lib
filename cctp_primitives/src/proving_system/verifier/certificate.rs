use crate::utils::data_structures::BackwardTransfer;
use crate::utils::get_cert_data_hash;
use crate::{
    proving_system::{error::ProvingSystemError, verifier::UserInputs},
    type_mapping::FieldElement,
};

/// All the data needed to reconstruct the aggregated input for the NaiveThresholdSignatureCircuit
/// included in the Certificate.
#[derive(Clone)]
pub struct CertificateProofUserInputs<'a> {
    pub constant: Option<&'a FieldElement>,
    pub sc_id: &'a FieldElement,
    pub epoch_number: u32,
    pub quality: u64,
    pub bt_list: Option<&'a [BackwardTransfer]>,
    pub custom_fields: Option<Vec<&'a FieldElement>>,
    pub end_cumulative_sc_tx_commitment_tree_root: &'a FieldElement,
    pub btr_fee: u64,
    pub ft_min_amount: u64,
    pub sc_prev_wcert_hash: Option<&'a FieldElement>,
}

impl UserInputs for CertificateProofUserInputs<'_> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        let mut inputs = Vec::new();

        if self.constant.is_some() {
            inputs.push(*self.constant.unwrap());
        }

        let cert_data_hash = get_cert_data_hash(
            self.sc_id,
            self.epoch_number,
            self.quality,
            self.bt_list,
            self.custom_fields.clone(),
            self.end_cumulative_sc_tx_commitment_tree_root,
            self.btr_fee,
            self.ft_min_amount,
        )
        .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;
        inputs.push(cert_data_hash);

        if self.sc_prev_wcert_hash.is_some() {
            inputs.push(*self.sc_prev_wcert_hash.unwrap());
        }

        Ok(inputs)
    }
}
