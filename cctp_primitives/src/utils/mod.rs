use algebra::ToBytes;
use crate::{
    utils::{
        commitment_tree::{bytes_to_field_elements, hash_vec},
    },
    type_mapping::{FieldElement, GINGER_MHT_POSEIDON_PARAMETERS, GingerMHT, Error, FIELD_SIZE, MC_PK_SIZE}
};
use primitives::FieldBasedMerkleTree;
use crate::utils::serialization::deserialize_from_buffer;

pub mod commitment_tree;
pub mod debug;
pub mod proving_system;
pub mod serialization;
pub mod poseidon_hash;
pub mod mht;

fn _get_root_from_field_vec(field_vec: Vec<FieldElement>, height: usize) -> Result<FieldElement, Error> {
    assert!(height <= GINGER_MHT_POSEIDON_PARAMETERS.nodes.len());
    if field_vec.len() > 0 {
        let mut mt =
            GingerMHT::init(height, 2usize.pow(height as u32));
        for fe in field_vec.into_iter(){
            mt.append(fe)?;
        }
        mt.finalize_in_place();
        mt.root().ok_or(Error::from("Failed to compute Merkle Tree root"))

    } else {
        Ok(GINGER_MHT_POSEIDON_PARAMETERS.nodes[height])
    }
}

/// Get the Merkle Root of a Binary Merkle Tree of height 12 built from the Backward Transfer list
pub fn get_bt_merkle_root(bt_list: &[(u64, [u8; MC_PK_SIZE])]) -> Result<FieldElement, Error>
{
    let mut buffer = Vec::new();
    for (amount, pk) in bt_list.iter() {
        amount.write(&mut buffer)?;
        pk.write(&mut buffer)?;
    }
    _get_root_from_field_vec(bytes_to_field_elements(buffer)?, 12)
}

/// Compute H(
pub fn get_cert_data_hash(
    constant: Option<&[u8; FIELD_SIZE]>,
    epoch_number: u32,
    quality: u64,
    bt_list: &[(u64, [u8; MC_PK_SIZE])],
    custom_fields: Option<&[[u8; FIELD_SIZE]]>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &[u8; FIELD_SIZE],
    btr_fee: u64,
    ft_min_amount: u64
) -> Result<FieldElement, Error>
{
    // Pack btr_fee and ft_min_amount into a single field element
    let fees_field_elements = {
        let fes = bytes_to_field_elements(vec![btr_fee, ft_min_amount])?;
        assert_eq!(fes.len(), 1);
        fes[0]
    };

    // Pack epoch_number and quality into separate field elements (for simplicity of treatment in
    // the circuit)
    let epoch_number_fe = FieldElement::from(epoch_number);
    let quality_fe = FieldElement::from(quality);

    // Compute bt_list merkle root
    let bt_root = get_bt_merkle_root(bt_list)?;

    // Read end_cumulative_sc_tx_commitment_tree_root as field element
    let end_cumulative_sc_tx_commitment_tree_root_fe = deserialize_from_buffer::<FieldElement>(&end_cumulative_sc_tx_commitment_tree_root[..])?;

    // Compute cert sysdata hash
    let cert_sysdata_hash = hash_vec(
        vec![epoch_number_fe, bt_root, quality_fe, end_cumulative_sc_tx_commitment_tree_root_fe, fees_field_elements]
    )?;

    // Final field elements to hash
    let mut fes = Vec::new();

    // Read constant (if present) as FieldElement and add it to fes
    if constant.is_some() {
        fes.push(deserialize_from_buffer::<FieldElement>(&constant.unwrap()[..])?)
    }

    // Compute linear hash of custom fields (if present) and add the digest to fes
    if custom_fields.is_some() {
        let custom_fes = custom_fields
            .unwrap()
            .iter()
            .map(|custom_field_bytes| deserialize_from_buffer::<FieldElement>(&custom_field_bytes[..]))
            .collect::<Result<Vec<_>, _>>()?;
        fes.push(hash_vec(custom_fes)?)
    }

    // Put cert_sysdata_hash
    fes.push(cert_sysdata_hash);

    hash_vec(fes)
}