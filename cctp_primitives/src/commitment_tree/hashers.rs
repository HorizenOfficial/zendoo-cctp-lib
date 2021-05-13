use algebra::FromBytes;
use crate::commitment_tree::{FieldElement, FIELD_SIZE};
use crate::commitment_tree::utils::*;

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
        .update(pub_key)?
        .update(tx_hash)?
        .update(out_idx)?;

    debug_assert!(accumulator.clone().get_field_elements().unwrap().len() == 3);
    accumulator.compute_field_hash()
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(
    sc_fee:  u64,
    sc_request_data: &[[u8; FIELD_SIZE]],
    mc_destination_address: &[u8; 20],
    tx_hash: &[u8; 32],
    out_idx: u32
) -> Result<FieldElement, Error>
{
    // ceil(256 + 160 + 96/254) = ceil(512/254) = 3 fes
    let mut fes = ByteAccumulator::init()
        .update(sc_fee)?
        .update(mc_destination_address)?
        .update(tx_hash)?
        .update(out_idx)?
        .get_field_elements()?;

    debug_assert!(fes.len() == 3);

    // sc_request_data elements MUST BE field elements
    for fe in sc_request_data.iter() {
        fes.push(FieldElement::read(&fe[..])?);
    }

    Ok(hash_vec(fes))
}

pub fn get_cert_data_hash(
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64,[u8; 20])],
    custom_fields: Option<&[[u8; FIELD_SIZE]]>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[u8; FIELD_SIZE],
    btr_fee: u64,
    ft_min_amount: u64
) -> Result<FieldElement, Error>
{
    // Pack btr_fee and ft_min_amount into a single field element
    let fees_field_elements = ByteAccumulator::init()
        .update(btr_fee)?
        .update(ft_min_amount)?
        .get_field_elements()?;
    assert_eq!(fees_field_elements.len(), 1);

    // Pack epoch_number and quality into separate field elements (for simplicity of treatment in
    // the circuit)
    let epoch_number_fe = FieldElement::from(epoch_number);
    let quality_fe = FieldElement::from(quality);

    // Compute bt_list merkle root
    let bt_root = get_bt_merkle_root(bt_list)?;

    // Read end_cumulative_sc_tx_commitment_tree_root as field element
    let end_cumulative_sc_tx_commitment_tree_root_fe = FieldElement::read(&end_cumulative_sc_tx_commitment_tree_root[..])?;

    // Compute cert sysdata hash
    let cert_sysdata_hash = hash_vec(
        vec![epoch_number_fe, bt_root, quality_fe, end_cumulative_sc_tx_commitment_tree_root_fe, fees_field_elements[0]]
    );

    // Final field elements to hash
    let mut fes = Vec::new();

    // Compute linear hash of custom fields (if present) and add the digest to fes
    if custom_fields.is_some() {
        let custom_fes = custom_fields
            .unwrap()
            .iter()
            .map(|custom_field_bytes| FieldElement::read(&custom_field_bytes[..]))
            .collect::<Result<Vec<_>, _>>()?;
        fes.push(hash_vec(custom_fes))
    }

    // Add cert_sysdata_hash
    fes.push(cert_sysdata_hash);

    // Compute final hash
    Ok(hash_vec(fes))
}

// Computes FieldElement-based hash on the given Certificate data
pub fn hash_cert(
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64,[u8; 20])],
    custom_fields: Option<&[[u8; FIELD_SIZE]]>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[u8; FIELD_SIZE],
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
    cert_proving_system: u8,
    csw_proving_system: Option<u8>,
    mc_btr_request_data_length: u8,
    custom_field_elements_configs: &[u8],
    custom_bitvector_elements_configs: &[(u32, u32)],
    btr_fee: u64,
    ft_min_amount: u64,
    custom_creation_data: &[u8],
    constant: Option<&[u8; FIELD_SIZE]>,
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
        .update(pub_key)?
        .update(tx_hash)?
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
            .compute_field_hash()?
    );

    // Read constant into a field element if present
    if constant.is_some() { fes.push(FieldElement::read(&constant.unwrap()[..])?); }

    // Compute cert_verification_key hash and add it to fes
    fes.push(
        ByteAccumulator::init()
            .update(cert_verification_key)?
            .compute_field_hash()?
    );

    // Compute csw_verification_key hash (if present) and add it to fes
    fes.push(
        ByteAccumulator::init()
            .update(csw_verification_key)?
            .compute_field_hash()?
    );

    // Compute final hash
    Ok(hash_vec(fes))
}

// Computes FieldElement-based hash on the given Ceased Sidechain Withdrawal data
pub fn hash_csw(
    amount: u64,
    nullifier: &[u8; FIELD_SIZE],
    mc_pk_hash: &[u8; 20],
) -> Result<FieldElement, Error>
{
    // Pack amount and pk_hash into a single field element
    let mut fes = ByteAccumulator::init()
        .update(amount)?
        .update(mc_pk_hash)?
        .get_field_elements()?;
    debug_assert!(fes.len() == 1);

    // Push the nullifier to fes
    fes.push(FieldElement::read(&nullifier[..])?);

    // Return final hash
    Ok(hash_vec(fes))
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::hashers::{hash_fwt, hash_bwtr, hash_scc, hash_cert, hash_csw};
    use rand::Rng;
    use std::convert::{TryFrom, TryInto};
    use crate::commitment_tree::utils::{rand_vec, rand_fe, rand_fe_vec};

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
                &rand_fe_vec(5),
                &rand_vec(20).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            ).is_ok()
        );

        let bt = (rng.gen::<u64>(), <[u8; 20]>::try_from(rand_vec(20).as_slice()).unwrap());
        assert!(
            hash_cert(
                rng.gen(),
                rng.gen(),
                &vec![bt, bt],
                Some(&rand_fe_vec(2)),
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
                rng.gen(),
                Some(rng.gen()),
                rng.gen(),
                &rand_vec(10),
                &[(rng.gen(), rng.gen())],
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
                &rand_vec(20).try_into().unwrap()
            ).is_ok()
        );
    }
}
