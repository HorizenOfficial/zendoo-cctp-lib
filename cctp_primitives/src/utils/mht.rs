//! MerkleTree and MerklePath wrappers, used by cryptolibs.

use crate::type_mapping::{GingerMHT, FieldElement, GingerMHTPath, Error, FieldHash};
use primitives::{FieldBasedHash, FieldBasedMerkleTree, FieldBasedMerkleTreePath};

pub fn new_ginger_mht(height: usize, processing_step: usize) -> GingerMHT {
    GingerMHT::init(height, processing_step)
}

pub fn append_leaf_to_ginger_mht(tree: &mut GingerMHT, leaf: &FieldElement){
    tree.append(*leaf);
}

pub fn finalize_ginger_mht(tree: &GingerMHT) -> GingerMHT {
    tree.finalize()
}

pub fn finalize_ginger_mht_in_place(tree: &mut GingerMHT) {
    tree.finalize_in_place();
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

pub fn reset_ginger_mht(tree: &mut GingerMHT){
    tree.reset();
}

pub fn verify_ginger_merkle_path(
    path: &GingerMHTPath,
    height: usize,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify(height, leaf, root)
}

pub fn verify_ginger_merkle_path_without_length_check(
    path: &GingerMHTPath,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify_without_length_check(leaf, root)
}

pub fn is_path_leftmost(path: &GingerMHTPath) -> bool {
    path.is_leftmost()
}

pub fn is_path_rightmost(path: &GingerMHTPath) -> bool {
    path.is_rightmost()
}

pub fn are_right_leaves_empty(path: &GingerMHTPath) -> bool { path.are_right_leaves_empty() }

pub fn get_leaf_index_from_path(path: &GingerMHTPath) -> u64 {
    path.leaf_index() as u64
}

//TODO: Move to GingerLib
pub fn apply(path: &GingerMHTPath, leaf: &FieldElement) -> FieldElement
{
    let mut digest = FieldHash::init_constant_length(2, None);
    let mut prev_node = *leaf;
    for (sibling, direction) in path.get_raw_path().iter() {

        assert_eq!(sibling.len(), 1);
        assert!(*direction == 0 || *direction == 1);

        // Choose left and right hash according to direction
        let (left, right) = if *direction == 0{
            (prev_node, sibling[0].clone())
        } else {
            (sibling[0].clone(), prev_node)
        };

        // Compute the parent node
        prev_node = digest
            .update(left)
            .update(right)
            .finalize()
            .unwrap();

        digest.reset(None);
    }
    prev_node
}