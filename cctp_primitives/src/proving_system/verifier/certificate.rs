use crate::{
    type_mapping::{FIELD_SIZE, FieldElement, MC_PK_SIZE},
    proving_system::{
        verifier::{UserInputs, ZendooVerifier},
        error::ProvingSystemError,
    },
};
use crate::utils::get_cert_data_hash;

/// All the data needed to reconstruct the aggregated input for the NaiveThresholdSignatureCircuit
/// included in the Certificate.
pub struct CertificateProofUserInputs<'a> {
    pub constant:                                   Option<&'a [u8; FIELD_SIZE]>,
    pub epoch_number:                               u32,
    pub quality:                                    u64,
    pub bt_list:                                    &'a [(u64,[u8; MC_PK_SIZE])],
    pub custom_fields:                              Option<&'a [[u8; FIELD_SIZE]]>,
    pub end_cumulative_sc_tx_commitment_tree_root:  &'a [u8; FIELD_SIZE],
    pub btr_fee:                                    u64,
    pub ft_min_fee:                                 u64
}

impl UserInputs for CertificateProofUserInputs<'_> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {

        let aggregated_input = get_cert_data_hash(
            self.constant, self.epoch_number, self.quality, self.bt_list, self.custom_fields,
            self.end_cumulative_sc_tx_commitment_tree_root, self.btr_fee, self.ft_min_fee
        ).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        Ok(vec![aggregated_input])
    }
}

pub struct ZendooCertProofVerifier<'a>(std::marker::PhantomData<&'a ()>);

impl<'a> ZendooVerifier for ZendooCertProofVerifier<'a> {
    type Inputs = CertificateProofUserInputs<'a>;
}
