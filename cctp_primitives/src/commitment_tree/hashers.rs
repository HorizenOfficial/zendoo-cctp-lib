use algebra::ToBytes;
use crate::utils::{
    commitment_tree::*, get_cert_data_hash
};
use crate::type_mapping::*;
use crate::utils::serialization::deserialize_from_buffer;

// Computes FieldElement-based hash on the given Forward Transfer Transaction data
pub fn hash_fwt(
    amount: u64,
    pub_key: &[u8; 32],
    tx_hash: &[u8; 32],
    out_idx: u32
)-> Result<FieldElement, Error>
{
    // ceil(256 + 256 + 96/254) = ceil(608/254) = 3 fes
    let mut buffer = Vec::new();
    amount.write(&mut buffer)?;
    pub_key.write(&mut buffer)?;
    tx_hash.write(&mut buffer)?;
    out_idx.write(&mut buffer)?;

    hash_bytes(buffer)
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(
    sc_fee:  u64,
    sc_request_data: &[[u8; FIELD_SIZE]],
    mc_destination_address: &[u8; MC_PK_SIZE],
    tx_hash: &[u8; 32],
    out_idx: u32
) -> Result<FieldElement, Error>
{
    let mut buffer = Vec::new();
    sc_fee.write(&mut buffer)?;
    mc_destination_address.write(&mut buffer)?;
    tx_hash.write(&mut buffer)?;
    out_idx.write(&mut buffer)?;

    // ceil(256 + 160 + 96/254) = ceil(512/254) = 3 fes
    let mut fes = bytes_to_field_elements(buffer)?;

    // sc_request_data elements MUST BE field elements
    for fe in sc_request_data.iter() {
        fes.push(deserialize_from_buffer::<FieldElement>(&fe[..])?);
    }

    hash_vec(fes)
}

// Computes FieldElement-based hash on the given Certificate data
//TODO: Maybe we will put additional data ? I hope not :)
pub fn hash_cert(
    constant: Option<&[u8; FIELD_SIZE]>,
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64,[u8; MC_PK_SIZE])],
    custom_fields: Option<&[[u8; FIELD_SIZE]]>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[u8; FIELD_SIZE],
    btr_fee: u64,
    ft_min_fee: u64
) -> Result<FieldElement, Error>
{
    get_cert_data_hash(
        constant, epoch_number, quality, bt_list, custom_fields,
        end_cumulative_sc_tx_commitment_tree_root, btr_fee, ft_min_fee
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
    csw_proving_system: u8,
    mc_btr_request_data_length: u8,
    custom_field_elements_configs: &[u8],
    custom_bitvector_elements_configs: &[(u32, u32)],
    btr_fee: u64,
    ft_min_fee: u64,
    // TODO: verify if it's enough to add to the comm_tree just the Poseidonhash of the custom_creation_data (Oleksandr)
    custom_creation_data_hash: &[u8; FIELD_SIZE],
    constant: Option<&[u8; FIELD_SIZE]>,
    cert_verification_key_hash: &[u8; FIELD_SIZE],
    csw_verification_key_hash: Option<&[u8; FIELD_SIZE]>
) -> Result<FieldElement, Error>
{
    //TODO: Is there a reason why we deserialize tx_data_fes, sc_base_conf_fes and fees_fes separately ?
    //      Can't we concatenate them in a single byte array and then deserialize it ?

    // Init hash input
    let mut fes = Vec::new();

    // Convert tx data to field elements
    let mut tx_data_fes = {
        let mut buffer = Vec::new();

        amount.write(&mut buffer)?;
        pub_key.write(&mut buffer)?;
        tx_hash.write(&mut buffer)?;
        out_idx.write(&mut buffer)?;

        bytes_to_field_elements(buffer)
    }?;
    fes.append(&mut tx_data_fes);

    // Convert sc base configuration data into field elements
    let mut sc_base_conf_fes = {
        let mut buffer = Vec::new();

        withdrawal_epoch_length.write(&mut buffer)?;
        cert_proving_system.write(&mut buffer)?;
        csw_proving_system.write(&mut buffer)?;
        mc_btr_request_data_length.write(&mut buffer)?;

        bytes_to_field_elements(buffer)
    }?;
    fes.append(&mut sc_base_conf_fes);


    // Convert custom configuration data into field elements
    let mut custom_conf_data_fes = {
        let mut buffer = Vec::new();

        custom_field_elements_configs.write(&mut buffer)?;
        for (e1, e2) in custom_bitvector_elements_configs.iter() {
            e1.write(&mut buffer)?;
            e2.write(&mut buffer)?;
        }
        bytes_to_field_elements(buffer)
    }?;
    fes.append(&mut custom_conf_data_fes);

    // Pack btr_fee and ft_min_fee into a single field element
    fes.append(&mut bytes_to_field_elements(vec![btr_fee, ft_min_fee])?);

    // Read the other data as field elements if present and push it to fes
    fes.push(deserialize_from_buffer::<FieldElement>(&custom_creation_data_hash[..])?);

    if constant.is_some() { fes.push(deserialize_from_buffer::<FieldElement>(&constant.unwrap()[..])?); }

    fes.push(deserialize_from_buffer::<FieldElement>(&cert_verification_key_hash[..])?);

    if csw_verification_key_hash.is_some() {
        fes.push(deserialize_from_buffer::<FieldElement>(&csw_verification_key_hash.unwrap()[..])?);
    }

    // Compute final hash
    hash_vec(fes)
}

// Computes FieldElement-based hash on the given Ceased Sidechain Withdrawal data
//TODO verify with Oleksandr if we need to add the redeemScript (signature?)
pub fn hash_csw(
    amount: u64,
    nullifier: &[u8; FIELD_SIZE],
    mc_pk_hash: &[u8; MC_PK_SIZE],
) -> Result<FieldElement, Error>
{
    let mut fes = Vec::new();

    // Pack amount and pk_hash into a single field element
    let mut buffer = Vec::new();

    amount.write(&mut buffer)?;
    mc_pk_hash.write(&mut buffer)?;

    fes.append(&mut bytes_to_field_elements(buffer)?);

    // Push the nullifier to fes
    fes.push(deserialize_from_buffer::<FieldElement>(&nullifier[..])?);

    // Return final hash
    hash_vec(fes)
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::hashers::{hash_fwt, hash_bwtr, hash_scc, hash_cert, hash_csw};
    use rand::Rng;
    use std::convert::{TryFrom, TryInto};
    use crate::utils::commitment_tree::{rand_vec, rand_fe, rand_fe_vec};
    use crate::type_mapping::MC_PK_SIZE;

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
                &rand_vec(MC_PK_SIZE).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            ).is_ok()
        );

        let bt = (rng.gen::<u64>(), <[u8; MC_PK_SIZE]>::try_from(rand_vec(MC_PK_SIZE).as_slice()).unwrap());
        assert!(
            hash_cert(
                Some(&rand_fe()),
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
                rng.gen(),
                rng.gen(),
                &rand_vec(10),
                &[(rng.gen(), rng.gen())],
                rng.gen(),
                rng.gen(),
                &rand_fe(),
                Some(&rand_fe()),
                &rand_fe(),
                Some(&rand_fe())
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