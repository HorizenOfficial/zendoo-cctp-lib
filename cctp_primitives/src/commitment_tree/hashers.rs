use algebra::ToConstraintField;
use crate::commitment_tree::{FieldElement, FieldElementsMT};
use crate::commitment_tree::utils::{hash_vec, Error};
use primitives::bytes_to_bits;
use byteorder;
use byteorder::{WriteBytesExt, BigEndian};

// Computes FieldElement-based hash on the given Forward Transfer Transaction data
pub fn hash_fwt(amount: u64,
                pub_key: &[u8; 32],
                tx_hash: &[u8; 32],
                out_idx: u32)
    -> Result<FieldElement, Error> {
    // ceil(256 + 256 + 96/254) = ceil(608/254) = 3 fes
    let mut bytes = Vec::<u8>::new();

    bytes.write_u64::<BigEndian>(amount)?;
    bytes.extend(&pub_key.to_vec());
    bytes.extend(&tx_hash.to_vec());
    bytes.write_u32::<BigEndian>(out_idx)?;

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(sc_fee:  u64,
                 sc_request_data: &[FieldElement], // We are sure that these are field elements
                 mc_destination_address: &[u8; 20],
                 tx_hash: &[u8; 32],
                 out_idx: u32)
    -> Result<FieldElement, Error> {
    // ceil(256 + 160 + 96/254) = ceil(512/254) = 3 fes
    let mut bytes = Vec::<u8>::new();
    bytes.write_u64::<BigEndian>(sc_fee)?;
    bytes.extend(&mc_destination_address.to_vec());
    bytes.extend(&tx_hash.to_vec());
    bytes.write_u32::<BigEndian>(out_idx)?;
    let mut fes = bytes.to_field_elements()?;

    // These are already field elements
    fes.extend_from_slice(sc_request_data_fes);

    compute_constant_length_poseidon_hash(fes.len(), fes)
}

pub fn get_cert_data_hash(
    constant: FieldElement,
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64,[u8; 20])],
    custom_fields: &[FieldElement], //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[FieldElement],
    btr_fee: u64,
    ft_min_fee: u64
) -> Result<FieldElement, Error>
{
    fees_field_element = pack(btr_fee, ft_min_fee);
    sys_cert_data_hash = hash(epoch_number, quality, fees_field_element, merkle_root(bt_list));

    custom_fields_data_hash = hash(custom_fields);

    //constant and custom_fields can be optional and then not part of the cert_data_hash
    hash(constant, sys_cert_data_hash, custom_fields_data_hash)

    /*let mut bytes = Vec::<u8>::new();

    bytes.write_u32::<BigEndian>(epoch_number)?;
    bytes.write_u64::<BigEndian>(quality)?;
    bytes.extend(&cert_data_hash.to_vec());
    bytes.extend(&bt_list_to_bytes(bt_list)?); // TODO: We need to hash the merkle root not the whole list
    bytes.extend(&custom_fields_merkle_root.to_vec());
    bytes.extend(&end_cumulative_sc_tx_commitment_tree_root.to_vec());

    hash_bytes(&bytes)*/
}

// Computes FieldElement-based hash on the given Certificate data
//TODO: Maybe we will put additional data ? I hope not :)
pub fn hash_cert(
    constant: FieldElement,
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64,[u8; 20])],
    custom_fields: &[FieldElement], //includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[FieldElement],
    btr_fee: u64,
    ft_min_fee: u64
) -> Result<FieldElement, Error> {
    get_cert_data_hash(...)
}

// Computes FieldElement-based hash on the given Sidechain Creation Transaction data
pub fn hash_scc(amount: u64,
                pub_key: &[u8;32],
                tx_hash: &[u8;32],
                out_idx: u32,

                withdrawal_epoch_length: u32,
                cert_proving_system: u8,
                csw_proving_system: u8,
                mc_btr_request_data_length: u8,

                custom_field_elements_configs: &[u8],
                custom_bitvector_elements_configs: &[(u32,u32)],

                btr_fee: u64,
                ft_min_fee: u64,

                custom_creation_data_hash: FieldElement, //verify if it's enough to add to the comm_tree just the Poseidonhash of the custom_creation_data (Oleksandr)
                constant: Option<FieldElement>,
                cert_verification_key_hash: FieldElement,
                csw_verification_key_hash: Option<FieldElement>

)
    -> Result<FieldElement, Error> {

    let tx_fes = pack(amount, pub_key, tx_hash, out_idx);
    let sc_base_conf_fes= pack(withdrawal_epoch_length, cert_proving_system, csw_proving_system, mc_btr_request_data_length);

    let custom_config_hash = hash(custom_field_elements_configs, custom_bitvector_elements_configs);

    let fees_fes = pack(btr_fee, ft_min_fee);

    hash(tx_fes, sc_base_conf_fes, custom_config_hash, fees_fes, custom_creation_data_hash, constant, cert_verification_key_hash, csw_verification_key_hash);

   /* let mut bytes = Vec::<u8>::new();

    bytes.write_i64::<BigEndian>(amount)?;
    bytes.extend(&pub_key.to_vec());
    bytes.write_u32::<BigEndian>(withdrawal_epoch_length)?;
    bytes.extend(&custom_data.to_vec());
    if constant.is_some(){
        bytes.extend(&constant.unwrap().to_vec());
    }
    bytes.extend(&cert_verification_key.to_vec());
    if btr_verification_key.is_some(){
        bytes.extend(&btr_verification_key.unwrap().to_vec());
    }
    if csw_verification_key.is_some(){
        bytes.extend(&csw_verification_key.unwrap().to_vec());
    }
    bytes.extend(&tx_hash.to_vec());
    bytes.write_u32::<BigEndian>(out_idx)?;

    hash_bytes(&bytes)*/
}

// Computes FieldElement-based hash on the given Ceased Sidechain Withdrawal data
pub fn hash_csw(amount: u64,
                nullifier: FieldElement,
                pk_hash: &[u8;20],
                )
    -> Result<FieldElement, Error> {
    hash(pack(amount, pk_hash), nullifier);
    //TODO verify with Oleksandr if we need to add the redeemScript (signature?)

    /*let mut bytes = Vec::<u8>::new();

    bytes.write_i64::<BigEndian>(amount)?;
    bytes.extend(&nullifier.to_vec());
    bytes.extend(&pk_hash.to_vec());
    bytes.extend(&active_cert_data_hash.to_vec());

    hash_bytes(&bytes)*/
}

// Converts list of BTs to byte-array
fn bt_list_to_bytes(bt_list: &[(i64,[u8; 20])]) -> Result<Vec<u8>, Error>{
    let mut bytes = Vec::<u8>::new();
    for bt in bt_list {
        bytes.write_i64::<BigEndian>(bt.0)?;
        bytes.extend(bt.1.to_vec())
    }
    Ok(bytes)
}

// Computes FieldElement-based hash on the given byte-array
pub fn hash_bytes(bytes: &[u8]) -> Result<FieldElement, Error> {
    Ok(hash_vec(&bytes_to_field_elements(bytes)?))
}

// Converts byte-array into a sequence of FieldElements
fn bytes_to_field_elements(bytes: &[u8]) -> Result<Vec<FieldElement>, Error> {
    bytes_to_bits(bytes).to_field_elements()
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::hashers::{hash_fwt, hash_bwtr, hash_scc, hash_cert, bt_list_to_bytes, hash_csw};
    use rand::Rng;
    use std::convert::TryFrom;
    use crate::commitment_tree::utils::rand_vec;

    #[test]
    fn test_bt_list_to_bytes(){
        let bt0 = (2i64, <[u8; 20]>::try_from(vec![1u8; 20].as_slice()).unwrap());
        let bt1 = (4i64, <[u8; 20]>::try_from(vec![2u8; 20].as_slice()).unwrap());

        assert_eq!(
            bt_list_to_bytes(&vec![bt0, bt1]).unwrap(),
            vec![0, 0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                 0, 0, 0, 0, 0, 0, 0, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
        );
    }

    #[test]
    fn test_hashers(){
        let mut rng = rand::thread_rng();

        assert!(
            hash_fwt(
                rng.gen(),
                &rand_vec(32),
                &rand_vec(32),
                rng.gen()
            ).is_ok()
        );

        assert!(
            hash_bwtr(
                rng.gen(),
                &rand_vec(32),
                &rand_vec(32),
                &rand_vec(32),
                rng.gen()
            ).is_ok()
        );

        let bt = (rng.gen::<i64>(), <[u8; 20]>::try_from(rand_vec(20).as_slice()).unwrap());
        assert!(
            hash_cert(
                rng.gen(),
                rng.gen(),
                &rand_vec(32),
                &vec![bt, bt],
                &rand_vec(32),
                &rand_vec(32)
            ).is_ok()
        );

        assert!(
            hash_scc(
                rng.gen(),
                &rand_vec(32),
                rng.gen(),
                &rand_vec(32),
                Some(&rand_vec(32)),
                &rand_vec(1544),
                Some(&rand_vec(1544)),
                Some(&rand_vec(1544)),
                &rand_vec(32),
                rng.gen()
            ).is_ok()
        );

        assert!(
            hash_csw(
                rng.gen(),
                &rand_vec(32),
                &rand_vec(20),
                &rand_vec(32)
            ).is_ok()
        );
    }
}
