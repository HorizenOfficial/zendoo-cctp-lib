use primitives::{Coord, FieldBasedHash};
use std::path::Path;
use crate::commitment_tree::{FieldElement, FieldElementsSMT, FieldHash};
use rand::Rng;

pub type Error = Box<dyn std::error::Error>;

pub const fn pow2(power: usize) -> usize { 1 << power }

// Creates new FieldElement-based SMT
pub fn new_smt(db_path: &str, height: usize) -> Result<FieldElementsSMT, Error> {
    // Avoid overwriting external data in an already existing directory
    if Path::new(db_path.to_owned().as_str()).exists() {
        return Err("Specified db_path already exists".into())
        // std::fs::remove_dir_all(db_path)?; // for debugging
    }

    match FieldElementsSMT::new(
        height,
        true,
        db_path.to_owned()
    ) {
        Ok(mut tree) => {
            tree.set_persistency(false); // no need to store an underlying DB
            Ok(tree)
        },
        Err(e) => Err(Box::new(e))
    }
}

// Sequentially inserts leafs into an SMT by using a specified position which is incremented afterwards
// Returns false if there is no more place to insert a leaf
pub fn add_leaf(tree: &mut FieldElementsSMT, leaf: &FieldElement, pos: &mut usize, capacity: usize) -> bool {
    if *pos < capacity {
        tree.insert_leaf(Coord::new(0, *pos), *leaf); *pos += 1;
        true
    } else {
        false
    }
}

// Returns unique base path for a sidechain-tree correspondingly to its ID and using db_path as a prefix
pub fn sc_base_path(sc_id: &FieldElement, db_path: &str) -> Result<String, Error> {
    if !db_path.is_empty(){
        // Name of a directory shouldn't be too big, so length of sc_id string is reduced to 40-characters via Sha-1 hash to preserve uniqueness of the sc_id
        let sc_id_suffix = sha1::Sha1::from(sc_id.to_string()).digest().to_string();
        Ok(db_path.to_owned() + sc_id_suffix.as_str())
    } else {
        Err("Empty db_path".into())
    }
}

// Calculates hash of a sequentially concatenated data elements
pub fn hash_vec(data: &Vec<FieldElement>) -> FieldElement {
    let mut hasher = <FieldHash>::init(None);
    for &fe in data {
        hasher.update(fe);
    }
    hasher.finalize()
}

// Generated vector of random bytes
pub fn rand_vec(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0.. len).map(|_|rng.gen()).collect()
}
