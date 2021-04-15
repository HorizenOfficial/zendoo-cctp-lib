use crate::{
    type_mapping::*,
    proving_system::{
        init::{
            get_g1_committer_key, get_g2_committer_key
        },
        verifier::*,
        error::ProvingSystemError,
    },
};
use proof_systems::darlin::pcd::{GeneralPCD, simple_marlin::SimpleMarlinPCD, final_darlin::FinalDarlinPCD};
use rand::RngCore;
use std::collections::HashMap;

/// Updatable struct storing all the data required to verify a batch of proof.
/// The struct provides function to add new proofs and to verify a subset of them.
/// Data is not cleared automatically from the `verifier_data` HashMap after
/// the corresponding verification procedure has been performed.
pub struct ZendooBatchVerifier {
    verifier_data: HashMap<String, VerifierData>,
}

impl ZendooBatchVerifier {

    /// Constructor for Self, currently just the constructor for the HashMap.
    pub fn init() -> Self {
        Self {
            verifier_data: HashMap::new(),
        }
    }

    /// Add a proof, uniquely identified by `id`, to the batch of proof to be verified.
    pub fn add_zendoo_proof_verifier_data<V: ZendooVerifier>(
        &mut self,
        id:                         String,
        inputs:                    V::Inputs,
        proof_and_vk:               RawVerifierData
    ) -> Result<(), ProvingSystemError> {
        let usr_ins = inputs.get_circuit_inputs()?;

        // Deserialize and save proof, vk and public inputs
        let verifier_data = VerifierData::from_raw(proof_and_vk, usr_ins)
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

        self.verifier_data.insert(id, verifier_data);

        Ok(())
    }


    /// Perform batch verification of `proofs_vks_ins` returning the result of the verification
    /// procedure. If the verification procedure fails, it may be possible to get the index of
    /// the proof that has caused the failure: in that case the Err type Option<usize> will
    /// contain the index in `proofs_vks_ins` of the offending proof; otherwise, it will be set
    /// to None.
    fn batch_verify_proofs<R: RngCore>(
        proofs_vks_ins:  Vec<VerifierData>,
        g1_ck:           &CommitterKeyG1,
        g2_ck:           &CommitterKeyG2,
        rng:             &mut R,
    ) -> Result<bool, Option<usize>>
    {
        let batch_len = proofs_vks_ins.len();

        // Collect all data in (GeneralPCD, VerificationKey) pairs
        let pcds_vks = proofs_vks_ins
            .into_iter()
            .map(|proof_vk_ins| {
                match proof_vk_ins {
                    VerifierData::CoboundaryMarlin(proof, vk, ins) => {
                        (GeneralPCD::SimpleMarlin(SimpleMarlinPCD::<G1, Digest>::new(proof, ins)), vk)
                    },
                    VerifierData::Darlin(proof, vk, ins) => {
                        (GeneralPCD::FinalDarlin(FinalDarlinPCD::<G1, G2, Digest>::new(proof, ins)), vk)
                    },
                }
            }).collect::<Vec<_>>();

        // Collect PCDs and Vks in separate vecs
        let mut pcds = Vec::with_capacity(batch_len);
        let mut vks = Vec::with_capacity(batch_len);
        pcds_vks.into_iter().for_each(|(pcd, vk)| {
            pcds.push(pcd);
            vks.push(vk);
        });

        // Perform batch_verification
        let result = proof_systems::darlin::proof_aggregator::batch_verify_proofs(
            pcds.as_slice(), vks.as_slice(), g1_ck, g2_ck, rng
        )?;

        Ok(result)
    }

    /// Verify only the proofs whose id is contained in `ids`.
    /// If the verification procedure fails, it may be possible to get the id of
    /// the proof that has caused the failure.
    pub fn batch_verify_subset<R: RngCore>(
        &self,
        ids: Vec<String>,
        rng: &mut R,
    ) -> Result<bool, ProvingSystemError>
    {
        // Retrieve committer keys
        let g1_ck = get_g1_committer_key()?;
        let g2_ck = get_g2_committer_key()?;

        if ids.len() == 0 {
            Err(ProvingSystemError::NoProofsToVerify)
        } else {
            let to_verify = ids.iter().map(|id| {
                match self.verifier_data.get(id) {
                    Some(data) => Ok(data.clone()),
                    None => return Err(ProvingSystemError::ProofNotPresent(id.clone())),
                }
            }).collect::<Result<Vec<_>, ProvingSystemError>>()?;

            // Perform batch verifications of the requested proofs
            let res = Self::batch_verify_proofs(
                to_verify, g1_ck.as_ref().unwrap(),
                g2_ck.as_ref().unwrap(), rng
            );

            // Return the id of the first failing proof if it's possible to determine it
            if res.is_err() {
                match res.unwrap_err() {
                    Some(idx) => return Err(ProvingSystemError::FailedBatchVerification(Some(ids[idx].clone()))),
                    None => return Err(ProvingSystemError::FailedBatchVerification(None))
                }
            }

            Ok(res.unwrap())
        }
    }

    /// Verify all the proofs in `verifier_data`.
    /// If the verification procedure fails, it may be possible to get the id of
    /// the proof that has caused the failure.
    pub fn batch_verify_all<R: RngCore>(
        &self,
        rng: &mut R
    ) -> Result<bool, ProvingSystemError>
    {
        self.batch_verify_subset(self.verifier_data.keys().map(|k| k.clone()).collect::<Vec<_>>(), rng)
    }
}