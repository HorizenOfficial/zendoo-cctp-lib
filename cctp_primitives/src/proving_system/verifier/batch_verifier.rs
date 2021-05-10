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
    pub verifier_data: HashMap<u32, VerifierData>,
}

impl ZendooBatchVerifier {

    /// Constructor for Self, currently just the constructor for the HashMap.
    pub fn create() -> Self {
        Self {
            verifier_data: HashMap::new(),
        }
    }

    /// Add a proof, uniquely identified by `id`, to the batch of proof to be verified.
    pub fn add_zendoo_proof_verifier_data<V: ZendooVerifier>(
        &mut self,
        id:                         u32,
        inputs:                     V::Inputs,
        proof_and_vk:               RawVerifierData,
        check_proof:                bool,
        check_vk:                   bool,
    ) -> Result<(), ProvingSystemError> {
        let usr_ins = inputs.get_circuit_inputs()?;

        // Deserialize and save proof, vk and public inputs
        let verifier_data = VerifierData::from_raw(proof_and_vk, check_proof, check_vk, usr_ins)
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
        ids: Vec<u32>,
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

#[cfg(test)]
mod test {
    use super::*;
    use algebra::UniformRand;
    use proof_systems::darlin::tests::{
        simple_marlin::generate_test_data as generate_simple_marlin_test_data,
        final_darlin::generate_test_data as generate_final_darlin_test_data,
    };
    use crate::{
        proving_system::{
            init::{load_g1_committer_key, get_g1_committer_key, load_g2_committer_key, get_g2_committer_key},
            error::ProvingSystemError,
            verifier::{UserInputs, ZendooVerifier, RawVerifierData, certificate::CertificateProofUserInputs},
        },
        type_mapping::{FieldElement, G1, G2},
        utils::{
            serialization::serialize_to_buffer,
            commitment_tree::rand_fe,
            data_structures::BackwardTransfer
        }
    };
    use poly_commit::ipa_pc::UniversalParams;
    use rand::{thread_rng, Rng};
    use std::path::PathBuf;
    use serial_test::serial;

    // ***********************Tests with real test circuit*************************
    struct TestCircuitInputs {
        c: FieldElement,
        d: FieldElement
    }

    impl UserInputs for TestCircuitInputs {
        fn get_circuit_inputs(&self) -> Result<Vec<FieldElement>, ProvingSystemError>
        {
            Ok(vec![self.c, self.d])
        }
    }

    struct TestCircuitVerifier {}

    impl ZendooVerifier for TestCircuitVerifier { type Inputs = TestCircuitInputs; }

    fn get_params() -> (
        UniversalParams<G1>,
        UniversalParams<G2>,
        usize,
        usize,
        PathBuf,
        PathBuf,
    ) {

        let max_pow = 7usize;
        let segment_size = 1 << max_pow;

        // Init committer keys
        let mut g1_ck_path = std::env::temp_dir();
        g1_ck_path.push("ck_g1");

        let committer_key_g1 = {
            load_g1_committer_key(segment_size - 1, &g1_ck_path).unwrap();
            get_g1_committer_key().unwrap()
        }.as_ref().unwrap().clone();

        let params_g1 = UniversalParams::<G1> {
            comm_key: committer_key_g1.comm_key.clone(),
            h: committer_key_g1.h.clone(),
            s: committer_key_g1.s.clone(),
        };

        let mut g2_ck_path = std::env::temp_dir();
        g2_ck_path.push("ck_g2");

        let committer_key_g2 = {
            load_g2_committer_key(segment_size - 1, &g2_ck_path).unwrap();
            get_g2_committer_key().unwrap()
        }.as_ref().unwrap().clone();

        let params_g2 = UniversalParams::<G2> {
            comm_key: committer_key_g2.comm_key.clone(),
            h: committer_key_g2.h.clone(),
            s: committer_key_g2.s.clone(),
        };

        (params_g1, params_g2, max_pow, segment_size, g1_ck_path, g2_ck_path)
    }

    #[test]
    #[serial]
    fn random_single_verifier_test() {

        let num_proofs = 100;
        let generation_rng = &mut thread_rng();
        let (
            params_g1,
            params_g2,
            max_pow,
            segment_size,
            g1_ck_path,
            g2_ck_path
        ) = get_params();
        let num_constraints = segment_size;

        for _ in 0..num_proofs {

            // Randomly choose segment size
            let iteration_segment_size = 1 << (generation_rng.gen_range(2, max_pow));

            // Randomly choose if to generate a SimpleMarlinProof or a FinalDarlinProof
            let simple: bool = generation_rng.gen();
            let (verifier_data, usr_ins) = if simple {

                // Generate test CoboundaryMarlin proof
                let (iteration_pcds, iteration_vks) = generate_simple_marlin_test_data(
                    num_constraints - 1,
                    iteration_segment_size,
                    &params_g1,
                    1,
                    generation_rng
                );
                (
                    RawVerifierData::CoboundaryMarlin {
                        proof: serialize_to_buffer::<CoboundaryMarlinProof>(&iteration_pcds[0].proof).unwrap(),
                        vk:  serialize_to_buffer::<CoboundaryMarlinVerifierKey>(&iteration_vks[0]).unwrap()
                    },
                    TestCircuitInputs {
                        c: iteration_pcds[0].usr_ins[0],
                        d: iteration_pcds[0].usr_ins[1]
                    }
                )
            } else {

                // Generate test FinalDarlin proof
                let (iteration_pcds, iteration_vks) = generate_final_darlin_test_data(
                    num_constraints - 1,
                    iteration_segment_size,
                    &params_g1,
                    &params_g2,
                    1,
                    generation_rng
                );

                (
                    RawVerifierData::Darlin {
                        proof: serialize_to_buffer::<DarlinProof>(&iteration_pcds[0].final_darlin_proof).unwrap(),
                        vk:  serialize_to_buffer::<DarlinVerifierKey>(&iteration_vks[0]).unwrap()
                    },
                    TestCircuitInputs {
                        c: iteration_pcds[0].usr_ins[0],
                        d: iteration_pcds[0].usr_ins[1]
                    }
                )
            };

            // Verification success
            assert!(TestCircuitVerifier::verify_proof(
                &usr_ins,
                verifier_data.clone(),
                false,
                false,
                Some(generation_rng)
            ).unwrap());

            // Verification failure
            let wrong_usr_ins = TestCircuitInputs {
                c: generation_rng.gen(),
                d: generation_rng.gen()
            };

            let res = TestCircuitVerifier::verify_proof(
                &wrong_usr_ins,
                verifier_data,
                false,
                false,
                Some(generation_rng)
            );
            assert!(res.is_err() || !res.unwrap());
        }

        // Cleanup
        let _ = std::fs::remove_file(&g1_ck_path);
        let _ = std::fs::remove_file(&g2_ck_path);
    }

    #[test]
    #[serial]
    fn random_batch_verifier_test() {

        let num_proofs = 100;
        let generation_rng = &mut thread_rng();
        let mut batch_verifier = ZendooBatchVerifier::create();

        let (
            params_g1,
            params_g2,
            max_pow,
            segment_size,
            g1_ck_path,
            g2_ck_path
        ) = get_params();
        let num_constraints = segment_size;

        for i in 0..num_proofs {

            // Randomly choose segment size
            let iteration_segment_size = 1 << (generation_rng.gen_range(2, max_pow));

            // Randomly choose if to generate a SimpleMarlinProof or a FinalDarlinProof
            let simple: bool = generation_rng.gen();
            let (verifier_data, usr_ins) = if simple {

                // Generate test CoboundaryMarlin proof
                let (iteration_pcds, iteration_vks) = generate_simple_marlin_test_data(
                    num_constraints - 1,
                    iteration_segment_size,
                    &params_g1,
                    1,
                    generation_rng
                );
                (
                    RawVerifierData::CoboundaryMarlin {
                        proof: serialize_to_buffer::<CoboundaryMarlinProof>(&iteration_pcds[0].proof).unwrap(),
                        vk:  serialize_to_buffer::<CoboundaryMarlinVerifierKey>(&iteration_vks[0]).unwrap()
                    },
                    TestCircuitInputs {
                        c: iteration_pcds[0].usr_ins[0],
                        d: iteration_pcds[0].usr_ins[1]
                    }
                )
            } else {

                // Generate test FinalDarlin proof
                let (iteration_pcds, iteration_vks) = generate_final_darlin_test_data(
                    num_constraints - 1,
                    iteration_segment_size,
                    &params_g1,
                    &params_g2,
                    1,
                    generation_rng
                );

                (
                    RawVerifierData::Darlin {
                        proof: serialize_to_buffer::<DarlinProof>(&iteration_pcds[0].final_darlin_proof).unwrap(),
                        vk:  serialize_to_buffer::<DarlinVerifierKey>(&iteration_vks[0]).unwrap()
                    },
                    TestCircuitInputs {
                        c: iteration_pcds[0].usr_ins[0],
                        d: iteration_pcds[0].usr_ins[1]
                    }
                )
            };

            batch_verifier.add_zendoo_proof_verifier_data::<TestCircuitVerifier>(
                i,
                usr_ins,
                verifier_data,
                false,
                false,
            ).unwrap();
        }

        // Verify all proofs
        assert!(batch_verifier.batch_verify_all(generation_rng).unwrap());

        // Replace the inputs of one of the proof at random and check that the
        // batch verification fails
        let index: u32 = generation_rng.gen_range(num_proofs/2, num_proofs);
        let wrong_ins = vec![
            FieldElement::rand(generation_rng),
            FieldElement::rand(generation_rng)
        ];
        match batch_verifier.verifier_data.get_mut(&index).unwrap() {
            VerifierData::CoboundaryMarlin(_, _, usr_ins) => {
                *usr_ins = wrong_ins
            },
            VerifierData::Darlin(_, _ ,usr_ins) => {
                *usr_ins = wrong_ins
            }
        }

        // Assert that the batch verification of all the proofs prior to that index is ok
        assert!(batch_verifier.batch_verify_subset(
            (0..num_proofs/2).collect::<Vec<_>>(),
            generation_rng,
        ).unwrap());

        // Assert that the batch verification of all the proofs following that index fails
        let res = batch_verifier.batch_verify_subset(
            (num_proofs/2..num_proofs).collect::<Vec<_>>(),
            generation_rng,
        );
        assert!(res.is_err());

        // We are able to get the index of the failing proof:
        match res.unwrap_err() {
            ProvingSystemError::FailedBatchVerification(id) => {
                let id = id.unwrap();
                assert_eq!(id, index);
            },
            _ => panic!(),
        }

        // Cleanup
        let _ = std::fs::remove_file(&g1_ck_path);
        let _ = std::fs::remove_file(&g2_ck_path);
    }

    // ************Tests with mocks for certificate and csw proofs batch verifier***************
    struct TestCertificateVerifier<'a>(std::marker::PhantomData<&'a ()>);

    impl<'a> ZendooVerifier for TestCertificateVerifier<'a> {
        type Inputs = CertificateProofUserInputs<'a>;

        fn verify_proof<R: RngCore>(
            inputs: &Self::Inputs,
            _proof_and_vk: RawVerifierData,
            _check_proof: bool,
            _check_vk: bool,
            _rng: Option<&mut R>
        ) -> Result<bool, ProvingSystemError>
        {
            let _ = inputs.get_circuit_inputs()?;
            Ok(true)
        }
    }

    struct TestZendooCertificateBatchVerifier<'a> {
        verifier_data: HashMap<u32, (RawVerifierData, CertificateProofUserInputs<'a>, bool)>,
    }

    impl<'a> TestZendooCertificateBatchVerifier<'a> {
        fn create() -> Self {
            Self {
                verifier_data: HashMap::new(),
            }
        }

        fn add_zendoo_proof_verifier_data(
            &mut self,
            id: u32,
            inputs: CertificateProofUserInputs<'a>,
            proof_and_vk: RawVerifierData,
            _check_proof: bool,
            _check_vk: bool,
            should_fail: bool, // Used here for testing
        ) -> Result<(), ProvingSystemError> {
            self.verifier_data.insert(id, (proof_and_vk, inputs, should_fail));
            Ok(())
        }

        fn batch_verify_proofs<R: RngCore>(
            proofs_vks_ins: Vec<(RawVerifierData, CertificateProofUserInputs<'a>, bool)>,
            _g1_ck: &CommitterKeyG1,
            _g2_ck: &CommitterKeyG2,
            rng: &mut R,
        ) -> Result<bool, Option<usize>>
        {
            for (i, (proof_vk, ins, should_fail)) in proofs_vks_ins.into_iter().enumerate() {
                if !should_fail {
                    match TestCertificateVerifier::verify_proof(
                        &ins,
                        proof_vk,
                        true,
                        true,
                        Some(rng)
                    )
                        {
                            Ok(res) => if !res { return Ok(false); },
                            Err(_) => return Err(Some(i))
                        }
                } else {
                    return Err(Some(i))
                }
            }

            Ok(true)
        }

        fn batch_verify_subset<R: RngCore>(
            &self,
            ids: Vec<u32>,
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

        fn batch_verify_all<R: RngCore>(
            &self,
            rng: &mut R
        ) -> Result<bool, ProvingSystemError>
        {
            self.batch_verify_subset(self.verifier_data.keys().map(|k| k.clone()).collect::<Vec<_>>(), rng)
        }
    }


    #[serial]
    #[test]
    fn dummy_certificate_batch_verifier_test() {
        let num_proofs = 100;
        let generation_rng = &mut thread_rng();
        let mut batch_verifier = TestZendooCertificateBatchVerifier::create();
        let (_, _, _, _, g1_ck_path, g2_ck_path) = get_params();
        let usr_ins = CertificateProofUserInputs {
            constant: None,
            epoch_number: 0,
            quality: 0,
            bt_list: &vec![BackwardTransfer::default()],
            custom_fields: None,
            end_cumulative_sc_tx_commitment_tree_root: &rand_fe(),
            btr_fee: 0,
            ft_min_amount: 0
        };
        for i in 0..num_proofs {
            // Randomly choose if to generate a SimpleMarlinProof or a FinalDarlinProof
            let simple: bool = generation_rng.gen();
            let (verifier_data, usr_ins) = if simple {
                (
                    RawVerifierData::CoboundaryMarlin { proof: vec![], vk: vec![] },
                    usr_ins.clone()
                )
            } else {
                (
                    RawVerifierData::Darlin { proof: vec![], vk: vec![] },
                    usr_ins.clone()
                )
            };

            batch_verifier.add_zendoo_proof_verifier_data(
                i,
                usr_ins,
                verifier_data,
                false,
                false,
                false
            ).unwrap();
        }

        // Verify all proofs
        assert!(batch_verifier.batch_verify_all(generation_rng).unwrap());

        // Trigger proof verification failure of one of the proofs at random index
        let index: u32 = generation_rng.gen_range(num_proofs/2, num_proofs);
        let (_, _, should_fail) = batch_verifier.verifier_data.get_mut(&index).unwrap();
        *should_fail = true;

        // Assert that the batch verification of all the proofs prior to that index is ok
        assert!(batch_verifier.batch_verify_subset(
            (0..num_proofs/2).collect::<Vec<_>>(),
            generation_rng,
        ).unwrap());

        // Assert that the batch verification of all the proofs following that index fails
        let res = batch_verifier.batch_verify_subset(
            (num_proofs/2..num_proofs).collect::<Vec<_>>(),
            generation_rng,
        );
        assert!(res.is_err());

        // We are able to get the index of the failing proof:
        match res.unwrap_err() {
            ProvingSystemError::FailedBatchVerification(id) => {
                let id = id.unwrap();
                assert_eq!(id, index);
            },
            _ => panic!(),
        }

        // Cleanup
        let _ = std::fs::remove_file(&g1_ck_path);
        let _ = std::fs::remove_file(&g2_ck_path);
    }
}