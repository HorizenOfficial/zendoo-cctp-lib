use crate::{
    type_mapping::{FIELD_SIZE, FieldElement, FieldHash},
    proving_system::{
        verifier::{UserInputs, ZendooVerifier},
        error::ProvingSystemError,
    },
    utils::{
        proof_system::get_bt_merkle_root,
        serialization::SerializationUtils,
    }
};
use primitives::FieldBasedHash;
use algebra::{
    ToConstraintField, ToBytes,
};

/// All the data needed to reconstruct the aggregated input for the NaiveThresholdSignatureCircuit
/// included in the Certificate.
pub struct CertificateProofUserInputs<'a> {
    end_epoch_mc_b_hash:        &'a [u8; 32],
    prev_end_epoch_mc_b_hash:   &'a [u8; 32],
    bt_list:                    Vec<(u64,[u8; 20])>,
    quality:                    u64,
    constant:                   Option<&'a [u8; FIELD_SIZE]>,
    proofdata:                  Option<&'a [u8; FIELD_SIZE]>,
}

impl UserInputs for CertificateProofUserInputs<'_> {
    fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError> {
        // Deserialize MC block hashes as field elements. Our current field size is 32 bytes, and
        // these hashes are 32 bytes too: this means that we are going to deserialize 4 field elements
        // in total.
        let end_epoch_mc_b_hash_fes = self.end_epoch_mc_b_hash.to_field_elements().unwrap();
        let prev_end_epoch_mc_b_hash_fes = self.prev_end_epoch_mc_b_hash.to_field_elements().unwrap();

        // Deserialize Backward Transfers and compute bt root
        let mut bt_fes_vec = Vec::with_capacity(self.bt_list.len());
        for bt in self.bt_list.iter() {
            let mut buffer = vec![];
            bt.0.write(&mut buffer)
                .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;
            bt.1.write(&mut buffer)
                .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;
            bt_fes_vec.append(&mut buffer.to_field_elements().unwrap())
        }
        let bt_root = get_bt_merkle_root(bt_fes_vec)
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        // Deserialize quality as field element
        let quality_fe = FieldElement::from(self.quality);

        // Compute WCertSysDataHash
        let wcert_sysdata_hash = {
            let mut digest = FieldHash::init(None);
            digest.update(quality_fe).update(bt_root);
            prev_end_epoch_mc_b_hash_fes.into_iter().for_each(|fe| {digest.update(fe);});
            end_epoch_mc_b_hash_fes.into_iter().for_each(|fe| {digest.update(fe);});
            digest.finalize()
        };

        // Compute aggregated input
        let mut digest = FieldHash::init(None);

        if self.constant.is_some(){
            digest.update(
                FieldElement::from_bytes(self.constant.unwrap())
                    .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            );
        }

        if self.proofdata.is_some(){
            digest.update(
                FieldElement::from_bytes(self.proofdata.unwrap())
                    .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
            );
        }

        digest.update(wcert_sysdata_hash);

        Ok(vec![digest.finalize()])
    }
}

pub struct ZendooCertProofVerifier<'a>(std::marker::PhantomData<&'a ()>);

impl<'a> ZendooVerifier for ZendooCertProofVerifier<'a> {
    type Inputs = CertificateProofUserInputs<'a>;
}