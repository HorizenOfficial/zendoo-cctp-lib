use crate::utils::data_structures::BackwardTransfer;
use crate::{
    type_mapping::{Error, FieldElement, GingerMHT, GINGER_MHT_POSEIDON_PARAMETERS},
    utils::commitment_tree::{hash_vec, DataAccumulator},
};
use primitives::FieldBasedMerkleTree;

pub mod commitment_tree;
pub mod data_structures;
pub mod debug;
pub mod mht;
pub mod poseidon_hash;
pub mod serialization;

fn _get_root_from_field_vec(
    field_vec: Vec<FieldElement>,
    height: usize,
) -> Result<FieldElement, Error> {
    if height > GINGER_MHT_POSEIDON_PARAMETERS.nodes.len() {
        Err(format!(
            "Height {} is bigger then GINGER_MHT_POSEIDON_PARAMETERS nodes len {}",
            height,
            GINGER_MHT_POSEIDON_PARAMETERS.nodes.len()
        ))?
    }

    if field_vec.len() > 0 {
        let mut mt = GingerMHT::init(height, 2usize.pow(height as u32))?;
        for fe in field_vec.into_iter() {
            mt.append(fe)?;
        }
        mt.finalize_in_place()?;
        mt.root()
            .ok_or(Error::from("Failed to compute Merkle Tree root"))
    } else {
        Ok(GINGER_MHT_POSEIDON_PARAMETERS.nodes[height])
    }
}

/// Get the Merkle Root of a Binary Merkle Tree of height 12 built from the Backward Transfer list
pub fn get_bt_merkle_root(bt_list: Option<&[BackwardTransfer]>) -> Result<FieldElement, Error> {
    let leaves = if bt_list.is_some() {
        let bt_list = bt_list.unwrap();
        let mut leaves = Vec::with_capacity(bt_list.len());
        for bt in bt_list.iter() {
            let bt_fes = DataAccumulator::init().update(bt)?.get_field_elements()?;
            assert_eq!(bt_fes.len(), 1);
            leaves.push(bt_fes[0]);
        }
        leaves
    } else {
        vec![]
    };

    _get_root_from_field_vec(leaves, 12)
}

pub fn get_cert_data_hash(
    sc_id: &FieldElement,
    epoch_number: u32,
    quality: u64,
    bt_list: Option<&[BackwardTransfer]>,
    custom_fields: Option<Vec<&FieldElement>>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
) -> Result<FieldElement, Error> {
    // Compute bt_list merkle root
    let bt_root = get_bt_merkle_root(bt_list)?;

    // Compute linear hash of custom fields (if present)
    let mut custom_fields_hash = None;

    if custom_fields.is_some() {
        let custom_fes = custom_fields
            .unwrap()
            .into_iter()
            .map(|custom_field| *custom_field)
            .collect::<Vec<_>>();
        custom_fields_hash = Some(hash_vec(custom_fes)?)
    }

    get_cert_data_hash_from_bt_root_and_custom_fields_hash(
        sc_id,
        epoch_number,
        quality,
        bt_root,
        custom_fields_hash,
        end_cumulative_sc_tx_commitment_tree_root,
        btr_fee,
        ft_min_amount,
    )
}

pub fn get_cert_data_hash_from_bt_root_and_custom_fields_hash(
    sc_id: &FieldElement,
    epoch_number: u32,
    quality: u64,
    bt_root: FieldElement,
    custom_fields_hash: Option<FieldElement>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
    end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
) -> Result<FieldElement, Error> {
    // Pack btr_fee and ft_min_amount into a single field element
    let fees_field_elements = DataAccumulator::init()
        .update(btr_fee)?
        .update(ft_min_amount)?
        .get_field_elements()?;

    assert_eq!(fees_field_elements.len(), 1);

    // Pack epoch_number and quality into separate field elements (for simplicity of treatment in
    // the circuit)
    let epoch_number_fe = FieldElement::from(epoch_number);
    let quality_fe = FieldElement::from(quality);

    // Compute cert sysdata hash
    let cert_sysdata_hash = hash_vec(vec![
        *sc_id,
        epoch_number_fe,
        bt_root,
        quality_fe,
        *end_cumulative_sc_tx_commitment_tree_root,
        fees_field_elements[0],
    ])?;

    // Final field elements to hash
    let mut fes = Vec::new();

    // Add custom fields hash if present
    if custom_fields_hash.is_some() {
        fes.push(custom_fields_hash.unwrap())
    }

    // Add cert_sysdata_hash
    fes.push(cert_sysdata_hash);

    // Compute final hash
    hash_vec(fes)
}

pub fn compute_sc_id(tx_hash: &[u8; 32], pos: u32) -> Result<FieldElement, Error> {
    DataAccumulator::init()
        .update(&tx_hash[..])?
        .update(pos)?
        .compute_field_hash_constant_length()
}
