use algebra::ToConstraintField;
use crate::type_mapping::{FieldElement, Error};
use crate::utils::commitment_tree_utils::hash_vec;
use primitives::bytes_to_bits;
use byteorder;
use byteorder::{WriteBytesExt, BigEndian};

// Computes FieldElement-based hash on the given Forward Transfer Transaction data
pub fn hash_fwt(amount: i64,
                pub_key: &[u8],
                tx_hash: &[u8],
                out_idx: u32)
    -> Result<FieldElement, Error> {
    let mut bytes = Vec::<u8>::new();

    bytes.write_i64::<BigEndian>(amount)?;
    bytes.extend(&pub_key.to_vec());
    bytes.extend(&tx_hash.to_vec());
    bytes.write_u32::<BigEndian>(out_idx)?;

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given Backward Transfer Request Transaction data
pub fn hash_bwtr(sc_fee:  i64,
                 sc_request_data: &[u8],
                 pk_hash: &[u8],
                 tx_hash: &[u8],
                 out_idx: u32)
    -> Result<FieldElement, Error> {
    let mut bytes = Vec::<u8>::new();

    bytes.write_i64::<BigEndian>(sc_fee)?;
    bytes.extend(&sc_request_data.to_vec());
    bytes.extend(&pk_hash.to_vec());
    bytes.extend(&tx_hash.to_vec());
    bytes.write_u32::<BigEndian>(out_idx)?;

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given Certificate data
pub fn hash_cert(epoch_number: u32,
                 quality: u64,
                 cert_data_hash: &[u8],
                 bt_list: &[(i64,[u8; 20])],
                 custom_fields_merkle_root: &[u8],
                 end_cumulative_sc_tx_commitment_tree_root: &[u8])
    -> Result<FieldElement, Error> {
    let mut bytes = Vec::<u8>::new();

    bytes.write_u32::<BigEndian>(epoch_number)?;
    bytes.write_u64::<BigEndian>(quality)?;
    bytes.extend(&cert_data_hash.to_vec());
    bytes.extend(&bt_list_to_bytes(bt_list)?);
    bytes.extend(&custom_fields_merkle_root.to_vec());
    bytes.extend(&end_cumulative_sc_tx_commitment_tree_root.to_vec());

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given Sidechain Creation Transaction data
pub fn hash_scc(amount: i64,
                pub_key: &[u8],
                withdrawal_epoch_length: u32,
                custom_data: &[u8],
                constant: Option<&[u8]>,
                cert_verification_key: &[u8],
                btr_verification_key: Option<&[u8]>,
                csw_verification_key: Option<&[u8]>,
                tx_hash: &[u8],
                out_idx: u32)
    -> Result<FieldElement, Error> {
    let mut bytes = Vec::<u8>::new();

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

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given Ceased Sidechain Withdrawal data
pub fn hash_csw(amount: i64,
                nullifier: &[u8],
                pk_hash: &[u8],
                active_cert_data_hash: &[u8])
    -> Result<FieldElement, Error> {
    let mut bytes = Vec::<u8>::new();

    bytes.write_i64::<BigEndian>(amount)?;
    bytes.extend(&nullifier.to_vec());
    bytes.extend(&pk_hash.to_vec());
    bytes.extend(&active_cert_data_hash.to_vec());

    hash_bytes(&bytes)
}

// Computes FieldElement-based hash on the given ID bytes
pub fn hash_id(sc_id: &[u8]) -> FieldElement { hash_bytes(sc_id).unwrap() }

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
    use crate::utils::commitment_tree_utils::rand_vec;

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
