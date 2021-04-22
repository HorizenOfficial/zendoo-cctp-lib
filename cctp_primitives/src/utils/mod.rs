use algebra::{ToBytes, ToConstraintField};
use crate::{
    utils::serialization::SerializationUtils,
    type_mapping::{FieldElement, GINGER_MHT_POSEIDON_PARAMETERS, GingerMHT, Error, FIELD_SIZE, FieldHash}
};
use primitives::{FieldBasedHash, FieldBasedMerkleTree};

pub mod commitment_tree;
pub mod debug;
pub mod proof_system;
pub mod serialization;

fn _get_root_from_field_vec(field_vec: Vec<FieldElement>, height: usize) -> Result<FieldElement, Error> {
    assert!(height <= GINGER_MHT_POSEIDON_PARAMETERS.nodes.len());
    if field_vec.len() > 0 {
        let mut mt =
            GingerMHT::init(height, 2usize.pow(height as u32));
        for fe in field_vec.into_iter(){
            mt.append(fe);
        }
        mt.finalize_in_place();
        mt.root().ok_or(Error::from("Failed to compute Merkle Tree root"))

    } else {
        Ok(GINGER_MHT_POSEIDON_PARAMETERS.nodes[height])
    }
}

/// Get the Merkle Root of a Binary Merkle Tree of height 12 built from the Backward Transfer list
pub fn get_bt_merkle_root(bt_list: Vec<FieldElement>) -> Result<FieldElement, Error>
{
    _get_root_from_field_vec(bt_list, 12)
}

/// Compute H(epoch_number, curr_cumulative_sc_tx_comm_tree_root, MR(bt_list), quality, H(custom_fields))
pub fn get_wcert_sysdata_hash(
    curr_cumulative_sc_tx_comm_tree_root: &[u8; FIELD_SIZE],
    custom_fields:                        &[[u8; FIELD_SIZE]],
    epoch_number:                         u32,
    bt_list:                              &[(u64,[u8; 20])],
    quality:                              u64,
) -> Result<FieldElement, Error>
{
    // Deserialize epoch number
    let epoch_number_fe = FieldElement::from(epoch_number);

    // Deserialize curr_cumulative_sc_tx_comm_tree_root
    let curr_cumulative_sc_tx_comm_tree_root_fe = FieldElement::from_bytes(curr_cumulative_sc_tx_comm_tree_root)?;

    // Deserialize Backward Transfers and compute bt root
    let mut bt_fes_vec = Vec::with_capacity(bt_list.len());
    for bt in bt_list.iter() {
        let mut buffer = vec![];
        bt.0.write(&mut buffer)?;
        bt.1.write(&mut buffer)?;
        bt_fes_vec.append(&mut buffer.to_field_elements().unwrap())
    }
    let bt_root = get_bt_merkle_root(bt_fes_vec)?;

    // Deserialize quality as field element
    let quality_fe = FieldElement::from(quality);

    // Deserialize custom fields hash
    let custom_field_hash_fe = {

        let mut custom_fields_digest = FieldHash::init_constant_length(
            custom_fields.len(), None
        );

        for custom_field in custom_fields.iter() {
            let custom_field_fe = FieldElement::from_bytes(custom_field)?;
            custom_fields_digest.update(custom_field_fe);
        }

        custom_fields_digest.finalize()
    }?;

    // Compute WCertSysDataHash
    let wcert_sysdata_hash = {
        let mut digest = FieldHash::init_constant_length(5, None);
        digest
            .update(epoch_number_fe)
            .update(curr_cumulative_sc_tx_comm_tree_root_fe)
            .update(bt_root)
            .update(quality_fe)
            .update(custom_field_hash_fe)
            .finalize()
    }?;

    Ok(wcert_sysdata_hash)
}