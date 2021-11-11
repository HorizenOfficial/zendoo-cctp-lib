//! MerkleTree and MerklePath wrappers, used by cryptolibs.

use crate::type_mapping::{Error, FieldElement, GingerMHT, GingerMHTPath};
use primitives::{FieldBasedMerkleTree, FieldBasedMerkleTreePath};

pub fn new_ginger_mht(height: usize, processing_step: usize) -> Result<GingerMHT, Error> {
    GingerMHT::init(height, processing_step)
}

pub fn append_leaf_to_ginger_mht(tree: &mut GingerMHT, leaf: &FieldElement) -> Result<(), Error> {
    let _ = tree.append(*leaf)?;
    Ok(())
}

pub fn finalize_ginger_mht(tree: &GingerMHT) -> Result<GingerMHT, Error> {
    tree.finalize()
}

pub fn finalize_ginger_mht_in_place(tree: &mut GingerMHT) -> Result<(), Error> {
    tree.finalize_in_place()?;
    Ok(())
}

pub fn get_ginger_mht_root(tree: &GingerMHT) -> Option<FieldElement> {
    tree.root()
}

pub fn get_ginger_mht_path(tree: &GingerMHT, leaf_index: u64) -> Option<GingerMHTPath> {
    match tree.get_merkle_path(leaf_index as usize) {
        Some(path) => Some(path.into()),
        None => None,
    }
}

pub fn reset_ginger_mht(tree: &mut GingerMHT) {
    tree.reset();
}

pub fn verify_ginger_merkle_path(
    path: &GingerMHTPath,
    height: usize,
    leaf: &FieldElement,
    root: &FieldElement,
) -> Result<bool, Error> {
    path.verify(height, leaf, root)
}

pub fn verify_ginger_merkle_path_without_length_check(
    path: &GingerMHTPath,
    leaf: &FieldElement,
    root: &FieldElement,
) -> bool {
    path.verify_without_length_check(leaf, root)
}

pub fn is_path_leftmost(path: &GingerMHTPath) -> bool {
    path.is_leftmost()
}

pub fn is_path_rightmost(path: &GingerMHTPath) -> bool {
    path.is_rightmost()
}

pub fn are_right_leaves_empty(path: &GingerMHTPath) -> bool {
    path.are_right_leaves_empty()
}

pub fn get_leaf_index_from_path(path: &GingerMHTPath) -> u64 {
    path.leaf_index() as u64
}

pub fn get_root_from_path(path: &GingerMHTPath, leaf: &FieldElement) -> FieldElement {
    path.compute_root(leaf)
}
