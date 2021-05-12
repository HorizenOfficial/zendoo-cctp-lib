use crate::utils::{
    commitment_tree::*, get_cert_data_hash, data_structures::{BitVectorElementsConfig, BackwardTransfer},
};
use crate::proving_system::ProvingSystem;
use crate::type_mapping::*;

// Computes FieldElement-based hash on the given Forward Transfer Transaction data
pub fn hash_fwt(
    amount: u64,
    pub_key: &[u8; 32],
    tx_hash: &[u8; 32],
    out_idx: u32
)-> Result<FieldElement, Error>
{
    // ceil(256 + 256 + 96/254) = ceil(608/254) = 3 fes
    let mut accumulator = ByteAccumulator::init();
    accumulator
        .update(amount)?
        .update(&pub_key[..])?
        .update(&tx_hash[..])?
        .update(out_idx)?;

    debug_assert!(accumulator.clone().get_field_elements().unwrap().len() == 3);
    accumulator.compute_field_hash_constant_length()
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(
    sc_fee:  u64,
    sc_request_data: Vec<&FieldElement>,
    mc_destination_address: &[u8; MC_PK_SIZE],
    tx_hash: &[u8; 32],
    out_idx: u32
) -> Result<FieldElement, Error>
{
    // ceil(256 + 160 + 96/254) = ceil(512/254) = 3 fes
    let mut fes = ByteAccumulator::init()
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
    epoch_number: u32,
    quality: u64,
    bt_list: &[BackwardTransfer],
    custom_fields: Option<Vec<&FieldElement>>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64
) -> Result<FieldElement, Error>
{
    get_cert_data_hash(
        epoch_number, quality, bt_list, custom_fields,
        end_cumulative_sc_tx_commitment_tree_root, btr_fee, ft_min_amount
    )
}

// Computes FieldElement-based hash on the given Sidechain Creation Transaction data
pub fn hash_scc(
    amount: u64,
    pub_key: &[u8; 32],
    tx_hash: &[u8; 32],
    out_idx: u32,
    withdrawal_epoch_length: u32,
    cert_proving_system: ProvingSystem,
    csw_proving_system: Option<ProvingSystem>,
    mc_btr_request_data_length: u8,
    custom_field_elements_configs: &[u8],
    custom_bitvector_elements_configs: &[BitVectorElementsConfig],
    btr_fee: u64,
    ft_min_amount: u64,
    custom_creation_data: &[u8],
    constant: Option<&FieldElement>,
    cert_verification_key: &[u8],
    csw_verification_key: Option<&[u8]>
) -> Result<FieldElement, Error>
{
    // Init hash input
    let mut fes = Vec::new();

    // Convert tx data to field elements
    // ceil(256 + 256 + 96/254) = ceil(608/254) = 3 fes
    let mut tx_data_fes = ByteAccumulator::init()
        .update(amount)?
        .update(&pub_key[..])?
        .update(&tx_hash[..])?
        .update(out_idx)?
        .get_field_elements()?;
    debug_assert!(tx_data_fes.len() == 3);
    fes.append(&mut tx_data_fes);


    // Convert sc base configuration data into field elements
    let mut sc_base_conf_fes = {
        let mut accumulator = ByteAccumulator::init();
        accumulator
            .update(withdrawal_epoch_length)?
            .update(cert_proving_system)?;
        if csw_proving_system.is_some() { accumulator.update(csw_proving_system.unwrap())?; }
        accumulator
            .update(mc_btr_request_data_length)?
            .get_field_elements()
    }?;
    fes.append(&mut sc_base_conf_fes);

    // Convert custom configuration data into field elements
    let mut custom_conf_data_fes = ByteAccumulator::init()
        .update(custom_field_elements_configs)?
        .update(custom_bitvector_elements_configs)?
        .get_field_elements()?;
    fes.append(&mut custom_conf_data_fes);

    // Pack btr_fee and ft_min_amount into a single field element
    let mut fees_field_elements = ByteAccumulator::init()
        .update(btr_fee)?
        .update(ft_min_amount)?
        .get_field_elements()?;
    debug_assert!(fees_field_elements.len() == 1);
    fes.append(&mut fees_field_elements);

    // Compute custom_creation_data hash and add it to fes
    fes.push(
        ByteAccumulator::init()
            .update(custom_creation_data)?
            .compute_field_hash_constant_length()?
    );

    if constant.is_some() { fes.push(*constant.unwrap()); }

    // Compute cert_verification_key hash and add it to fes
    fes.push(
        ByteAccumulator::init()
            .update(cert_verification_key)?
            .compute_field_hash_constant_length()?
    );

    // Compute csw_verification_key hash (if present) and add it to fes
    if csw_verification_key.is_some() {
        fes.push(
            ByteAccumulator::init()
                .update(csw_verification_key.unwrap())?
                .compute_field_hash_constant_length()?
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
) -> Result<FieldElement, Error>
{
    // Pack amount and pk_hash into a single field element
    let mut fes = ByteAccumulator::init()
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
    use crate::commitment_tree::hashers::{hash_fwt, hash_bwtr, hash_scc, hash_cert, hash_csw};
    use crate::type_mapping::MC_PK_SIZE;
    use crate::utils::{
        data_structures::{BitVectorElementsConfig, BackwardTransfer},
        commitment_tree::{rand_vec, rand_fe, rand_fe_vec}
    };
    use crate::proving_system::ProvingSystem;
    use rand::Rng;
    use std::convert::TryInto;

    #[test]
    fn test_hashers(){
        let mut rng = rand::thread_rng();

        assert!(
            hash_fwt(
                rng.gen(),
                &rand_vec(32).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            ).is_ok()
        );

        assert!(
            hash_bwtr(
                rng.gen(),
                rand_fe_vec(5).iter().collect(),
                &rand_vec(MC_PK_SIZE).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            ).is_ok()
        );

        assert!(
            hash_cert(
                rng.gen(),
                rng.gen(),
                &vec![BackwardTransfer::default(); 10],
                Some(rand_fe_vec(2).iter().collect()),
                &rand_fe(),
                rng.gen(),
                rng.gen(),
            ).is_ok()
        );

        assert!(
            hash_scc(
                rng.gen(),
                &rand_vec(32).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen(),
                rng.gen(),
                ProvingSystem::CoboundaryMarlin,
                Some(ProvingSystem::CoboundaryMarlin),
                rng.gen(),
                &rand_vec(10),
                &vec![BitVectorElementsConfig::default(); 10],
                rng.gen(),
                rng.gen(),
                &rand_vec(100),
                Some(&rand_fe()),
                &rand_vec(100),
                Some(&rand_vec(100))
            ).is_ok()
        );

        assert!(
            hash_csw(
                rng.gen(),
                &rand_fe(),
                &rand_vec(MC_PK_SIZE).try_into().unwrap()
            ).is_ok()
        );
    }
}