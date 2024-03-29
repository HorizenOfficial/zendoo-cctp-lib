use crate::type_mapping::*;
use crate::utils::{
    commitment_tree::*,
    data_structures::{BackwardTransfer, BitVectorElementsConfig},
    get_cert_data_hash,
};

// Computes FieldElement-based hash on the given Forward Transfer Transaction data
pub fn hash_fwt(
    amount: u64,
    pub_key: &[u8; 32],
    mc_return_address: &[u8; 20],
    tx_hash: &[u8; 32],
    out_idx: u32,
) -> Result<FieldElement, Error> {
    // ceil(256 + 256 + 160 + 96/254) = ceil(768/254) = 4 fes
    let mut accumulator = DataAccumulator::init();
    accumulator
        .update(amount)?
        .update(&pub_key[..])?
        .update(&mc_return_address[..])?
        .update(&tx_hash[..])?
        .update(out_idx)?;

    debug_assert!(accumulator.get_field_elements().unwrap().len() == 4);
    accumulator.compute_field_hash_constant_length()
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(
    sc_fee: u64,
    sc_request_data: Vec<&FieldElement>,
    mc_destination_address: &[u8; MC_PK_SIZE],
    tx_hash: &[u8; 32],
    out_idx: u32,
) -> Result<FieldElement, Error> {
    // ceil(256 + 160 + 96/254) = ceil(512/254) = 3 fes
    let mut fes = DataAccumulator::init()
        .update(sc_fee)?
        .update(&mc_destination_address[..])?
        .update(&tx_hash[..])?
        .update(out_idx)?
        .get_field_elements()?;

    debug_assert!(fes.len() == 3);

    // sc_request_data elements MUST BE field elements
    for fe in sc_request_data.into_iter() {
        fes.push(*fe);
    }

    hash_vec(fes)
}

// Computes FieldElement-based hash on the given Certificate data
pub fn hash_cert(
    sc_id: &FieldElement,
    epoch_number: u32,
    quality: u64,
    bt_list: Option<&[BackwardTransfer]>,
    custom_fields: Option<Vec<&FieldElement>>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
) -> Result<FieldElement, Error> {
    get_cert_data_hash(
        sc_id,
        epoch_number,
        quality,
        bt_list,
        custom_fields,
        end_cumulative_sc_tx_commitment_tree_root,
        btr_fee,
        ft_min_amount,
    )
}

// Computes FieldElement-based hash on the given Sidechain Creation Transaction data
pub fn hash_scc(
    amount: u64,
    pub_key: &[u8; 32],
    tx_hash: &[u8; 32],
    out_idx: u32,
    withdrawal_epoch_length: u32,
    mc_btr_request_data_length: u8,
    custom_field_elements_configs: Option<&[u8]>,
    custom_bitvector_elements_configs: Option<&[BitVectorElementsConfig]>,
    btr_fee: u64,
    ft_min_amount: u64,
    custom_creation_data: Option<&[u8]>,
    constant: Option<&FieldElement>,
    cert_verification_key: &[u8],
    csw_verification_key: Option<&[u8]>,
) -> Result<FieldElement, Error> {
    // Init hash input
    let mut fes = Vec::new();

    // Convert tx data to field elements
    // ceil(256 + 256 + 96/254) = ceil(608/254) = 3 fes
    let mut tx_data_fes = DataAccumulator::init()
        .update(amount)?
        .update(&pub_key[..])?
        .update(&tx_hash[..])?
        .update(out_idx)?
        .get_field_elements()?;
    debug_assert!(tx_data_fes.len() == 3);
    fes.append(&mut tx_data_fes);

    // Convert sc base configuration data into field elements
    let mut sc_base_conf_fes = {
        let mut accumulator = DataAccumulator::init();
        accumulator
            .update(withdrawal_epoch_length)?
            .update(mc_btr_request_data_length)?
            .get_field_elements()
    }?;
    fes.append(&mut sc_base_conf_fes);

    // Convert custom configuration data into field elements
    if custom_field_elements_configs.is_some() || custom_bitvector_elements_configs.is_some() {
        let mut digest = DataAccumulator::init();

        if custom_field_elements_configs.is_some() {
            digest.update(custom_field_elements_configs.unwrap())?;
        }

        if custom_bitvector_elements_configs.is_some() {
            digest.update(custom_bitvector_elements_configs.unwrap())?;
        }

        let mut custom_conf_data_fes = digest.get_field_elements()?;

        fes.append(&mut custom_conf_data_fes);
    }

    // Pack btr_fee and ft_min_amount into a single field element
    let mut fees_field_elements = DataAccumulator::init()
        .update(btr_fee)?
        .update(ft_min_amount)?
        .get_field_elements()?;
    debug_assert!(fees_field_elements.len() == 1);
    fes.append(&mut fees_field_elements);

    // Compute custom_creation_data hash and add it to fes
    if custom_creation_data.is_some() {
        fes.push(
            DataAccumulator::init()
                .update(custom_creation_data.unwrap())?
                .compute_field_hash_constant_length()?,
        );
    }

    if let Some(constant) = constant {
        fes.push(*constant);
    }

    // Compute cert_verification_key hash and add it to fes
    fes.push(
        DataAccumulator::init()
            .update(cert_verification_key)?
            .compute_field_hash_constant_length()?,
    );

    // Compute csw_verification_key hash (if present) and add it to fes
    if csw_verification_key.is_some() {
        fes.push(
            DataAccumulator::init()
                .update(csw_verification_key.unwrap())?
                .compute_field_hash_constant_length()?,
        );
    }

    // Compute final hash
    hash_vec(fes)
}

// Computes FieldElement-based hash on the given Ceased Sidechain Withdrawal data
pub fn hash_csw(
    amount: u64,
    nullifier: &FieldElement,
    mc_pk_hash: &[u8; MC_PK_SIZE],
) -> Result<FieldElement, Error> {
    // Pack amount and pk_hash into a single field element
    let mut fes = DataAccumulator::init()
        .update(amount)?
        .update(&mc_pk_hash[..])?
        .get_field_elements()?;
    debug_assert!(fes.len() == 1);

    // Push the nullifier to fes
    fes.push(*nullifier);

    // Return final hash
    hash_vec(fes)
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::hashers::{hash_bwtr, hash_cert, hash_csw, hash_fwt, hash_scc};
    use crate::type_mapping::MC_PK_SIZE;
    use crate::utils::{
        commitment_tree::{rand_fe, rand_fe_vec, rand_vec},
        data_structures::{BackwardTransfer, BitVectorElementsConfig},
    };
    use rand::Rng;
    use std::convert::TryInto;

    #[test]
    fn test_hashers() {
        let mut rng = rand::thread_rng();

        assert!(hash_fwt(
            rng.gen(),
            &rand_vec(32).try_into().unwrap(),
            &rand_vec(20).try_into().unwrap(),
            &rand_vec(32).try_into().unwrap(),
            rng.gen()
        )
        .is_ok());

        assert!(hash_bwtr(
            rng.gen(),
            rand_fe_vec(5).iter().collect(),
            &rand_vec(MC_PK_SIZE).try_into().unwrap(),
            &rand_vec(32).try_into().unwrap(),
            rng.gen()
        )
        .is_ok());

        let default_bt_vec = vec![BackwardTransfer::default(); 10];
        assert!(hash_cert(
            &rand_fe(),
            rng.gen(),
            rng.gen(),
            Some(default_bt_vec.as_slice()),
            Some(rand_fe_vec(2).iter().collect()),
            &rand_fe(),
            rng.gen(),
            rng.gen(),
        )
        .is_ok());

        assert!(hash_cert(
            &rand_fe(),
            rng.gen(),
            rng.gen(),
            None,
            None,
            &rand_fe(),
            rng.gen(),
            rng.gen(),
        )
        .is_ok());

        let default_bv_config = vec![BitVectorElementsConfig::default(); 10];
        assert!(hash_scc(
            rng.gen(),
            &rand_vec(32).try_into().unwrap(),
            &rand_vec(32).try_into().unwrap(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            Some(&rand_vec(10)),
            Some(default_bv_config.as_slice()),
            rng.gen(),
            rng.gen(),
            Some(&rand_vec(100)),
            Some(&rand_fe()),
            &rand_vec(100),
            Some(&rand_vec(100))
        )
        .is_ok());

        assert!(hash_scc(
            rng.gen(),
            &rand_vec(32).try_into().unwrap(),
            &rand_vec(32).try_into().unwrap(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            None,
            None,
            rng.gen(),
            rng.gen(),
            None,
            None,
            &rand_vec(100),
            None
        )
        .is_ok());

        assert!(hash_csw(
            rng.gen(),
            &rand_fe(),
            &rand_vec(MC_PK_SIZE).try_into().unwrap()
        )
        .is_ok());
    }
}
