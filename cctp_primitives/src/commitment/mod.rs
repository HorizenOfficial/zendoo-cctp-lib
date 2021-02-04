use primitives::{
    merkle_tree::field_based_mht::{
        smt::{BigMerkleTree, Coord},
        poseidon::MNT4753_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS,
        FieldBasedMerkleTreeParameters
    }, MNT4PoseidonHash, FieldBasedMerkleTreePrecomputedEmptyConstants
};
use algebra::{fields::mnt4753::Fr, Field};
use crate::commitment::sidechain_tree::{SidechainTree, SidechainSubtreeType};
use std::path::Path;

pub mod sidechain_tree;

pub type Error = Box<dyn std::error::Error>;

pub type FieldElement = Fr;
pub type FieldHash = MNT4PoseidonHash;

#[derive(Debug, Clone)]
pub struct GingerMerkleTreeParameters;

// Parameters of an underlying FieldElement-based Sparse Merkle Tree
impl FieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type Data = FieldElement;
    type H = FieldHash;
    const MERKLE_ARITY: usize = 2;
    const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> =
        Some(MHT_PARAMETERS);
}

// FieldElement-based Sparse Merkle Tree
pub type FieldElementsSMT = BigMerkleTree<GingerMerkleTreeParameters>;

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

// Checks for duplications in a sorted list of IDs
fn has_duplicates(sc_ids: &Vec<FieldElement>) -> bool {
    if sc_ids.len() > 1 {
        for i in 1.. sc_ids.len() {
            if sc_ids[i] == sc_ids[i - 1] { return true }
        }
    }
    false
}

const fn pow2(power: usize) -> usize { 1 << power }

// Tunable parameters
const CMT_SMT_HEIGHT:    usize = 12;
const CMT_SMT_CAPACITY:  usize = pow2(CMT_SMT_HEIGHT);
const CMT_PATH_SUFFIX:   &str = "_cmt";

pub struct CommitmentTree {
    sc_trees:   Vec<SidechainTree>, // ordered by IDs list of Sidechain Trees
    base_path:  String              // path for underlying SMT-based subtrees
}

impl CommitmentTree {

    // Creates a new instance of CommitmentTree consisting of an ordered by IDs list of Sidechain Trees (SCTs)
    // sc_ids  - is a list of SCT-IDs which should be non-empty and not containing duplicates;
    // db_path - is a path to some not yet created directory; it is needed for underlying Sparse Merkle Trees.
    //           NOTE: The last part of the db_path is used as a prefix of subdirectories name, i.e. for /tmp/cmt, the CMT's subdirectories will be placed in /tmp with their own directories names prefixed with 'cmt'
    pub fn create(sc_ids: &Vec<FieldElement>, db_path: &str) -> Result<CommitmentTree, Error> {
        if !db_path.is_empty(){
            if !sc_ids.is_empty() && sc_ids.len() <= CMT_SMT_CAPACITY {
                // Sorting SC IDs to make SidechainTrees ordered by their IDs
                let mut sc_ids_sorted = sc_ids.to_owned();
                sc_ids_sorted.sort();

                if !has_duplicates(&sc_ids_sorted) {
                    let mut sc_trees: Vec<SidechainTree> = Vec::new();
                    for sc_id in sc_ids_sorted {
                        sc_trees.push(SidechainTree::create(&sc_id, db_path)?)
                    }
                    Ok(
                        CommitmentTree{
                            sc_trees,
                            base_path: db_path.to_owned()
                        }
                    )
                } else {
                    Err("Duplicated Sidechain IDs".into())
                }
            } else {
                Err("Wrong size of sc_ids".into())
            }
        } else {
            Err("Empty db_path".into())
        }
    }

    // Gets reference to a SidechainTree with a specified ID; If such a SidechainTree doesn't exist returns None
    fn get_sc_tree(&self, sc_id: &FieldElement) -> Option<&SidechainTree> {
        self.sc_trees.iter().find(|sc_tree| sc_tree.id() == sc_id)
    }

    // Gets mutable reference to a SidechainTree with a specified ID; If such a SidechainTree doesn't exist returns None
    fn get_sc_tree_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTree> {
        self.sc_trees.iter_mut().find(|sc_tree| sc_tree.id() == sc_id)
    }

    // Adds leaf to a subtree of a specified type in a specified SCT
    fn add_subtree_leaf(&mut self, sc_id: &FieldElement, leaf: &FieldElement, subtree_type: SidechainSubtreeType) -> bool {
        if let Some(sc_tree) = self.get_sc_tree_mut(sc_id){
            match subtree_type {
                SidechainSubtreeType::FWT  => sc_tree.add_fwt (leaf),
                SidechainSubtreeType::BWTR => sc_tree.add_bwtr(leaf),
                SidechainSubtreeType::SCC  => sc_tree.add_scc (leaf),
                SidechainSubtreeType::CERT => sc_tree.add_cert(leaf),
                SidechainSubtreeType::CSW  => { sc_tree.set_csw(leaf); true }
            }
        } else {
            false
        }
    }

    // Gets commitment of a subtree of a specified type in a specified SCT
    fn get_subtree_commitment(&self, sc_id: &FieldElement, subtree_type: SidechainSubtreeType) -> Option<FieldElement> {
        if let Some(sc_tree) = self.get_sc_tree(sc_id){
            Some(
                match subtree_type {
                    SidechainSubtreeType::FWT  => sc_tree.get_fwt_commitment(),
                    SidechainSubtreeType::BWTR => sc_tree.get_bwtr_commitment(),
                    SidechainSubtreeType::SCC  => sc_tree.get_scc_commitment(),
                    SidechainSubtreeType::CERT => sc_tree.get_cert_commitment(),
                    SidechainSubtreeType::CSW  => panic!("There is no commitment for CSW")
                }
            )
        } else {
            None
        }
    }

    // Adds Forward Transfer Transaction's hash to the FWT subtree of the corresponding Sidechain tree
    // Returns false if Sidechain tree with a specified ID doesn't exist or FWT subtree has no place to add hash
    pub fn add_fwt(&mut self, sc_id: &FieldElement, fwt: &FieldElement) -> bool {
        self.add_subtree_leaf(sc_id, fwt, SidechainSubtreeType::FWT)
    }

    // Adds Backward Transfer Request Transaction's hash to the BWTR subtree of the corresponding Sidechain tree
    // Returns false if Sidechain tree with a specified ID doesn't exist or BWTR subtree has no place to add hash
    pub fn add_bwtr(&mut self, sc_id: &FieldElement, bwtr: &FieldElement) -> bool {
        self.add_subtree_leaf(sc_id, bwtr, SidechainSubtreeType::BWTR)
    }

    // Adds Sidechain Creation Transaction's hash to the SCC subtree of the corresponding Sidechain tree
    // Returns false if Sidechain tree with a specified ID doesn't exist or SCC subtree has no place to add hash
    pub fn add_scc(&mut self, sc_id: &FieldElement, scc: &FieldElement) -> bool {
        self.add_subtree_leaf(sc_id, scc, SidechainSubtreeType::SCC)
    }

    // Adds Certificate's hash to the CERT subtree of the corresponding Sidechain tree
    // Returns false if Sidechain tree with a specified ID doesn't exist or CERT subtree has no place to add hash
    pub fn add_cert(&mut self, sc_id: &FieldElement, cert: &FieldElement) -> bool {
        self.add_subtree_leaf(sc_id, cert, SidechainSubtreeType::CERT)
    }

    // Sets CSW's hash into the corresponding Sidechain tree
    // Returns false if Sidechain tree with a specified ID doesn't exist
    pub fn add_csw(&mut self, sc_id: &FieldElement, csw: &FieldElement) -> bool {
        self.add_subtree_leaf(sc_id, csw, SidechainSubtreeType::CSW)
    }

    // Gets commitment of the Forward Transfer Transactions subtree of a specified Sidechain tree
    // Returns None if Sidechain tree with a specified ID doesn't exist in current CommitmentTree
    pub fn get_fwt_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.get_subtree_commitment(sc_id, SidechainSubtreeType::FWT)
    }

    // Gets commitment of the Backward Transfer Requests Transactions subtree of a specified Sidechain tree
    // Returns None if Sidechain tree with a specified ID doesn't exist in current CommitmentTree
    pub fn get_bwtr_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.get_subtree_commitment(sc_id, SidechainSubtreeType::BWTR)
    }

    // Gets commitment of the Sidechain Creation Transactions subtree of a specified Sidechain tree
    // Returns None if Sidechain tree with a specified ID doesn't exist in current CommitmentTree
    pub fn get_scc_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.get_subtree_commitment(sc_id, SidechainSubtreeType::SCC)
    }

    // Gets commitment of the Certificates subtree of a specified Sidechain tree
    // Returns None if Sidechain tree with a specified ID doesn't exist in current CommitmentTree
    pub fn get_cert_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.get_subtree_commitment(sc_id, SidechainSubtreeType::CERT)
    }

    // Gets commitment of a specified Sidechain tree
    // Returns None if Sidechain tree with a specified ID doesn't exist in current CommitmentTree
    pub fn get_sc_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        if let Some(sc_tree) = self.get_sc_tree(sc_id){
            Some(sc_tree.get_commitment())
        } else {
            None
        }
    }

    // Gets overall commitment for a CommitmentTree
    // Returns None in case of error in `new_smt`
    // Note: The commitment is computed as a root of SCT's commitments SMT, where SCTs are preliminarily ordered by their ID
    pub fn get_commitment(&self) -> Option<FieldElement> {
        if let Ok(mut cmt) = new_smt(&(self.base_path.to_owned() + CMT_PATH_SUFFIX), CMT_SMT_HEIGHT){
            let mut pos = 0usize;
            for sct in &self.sc_trees {
                cmt.insert_leaf(Coord::new(0, pos), sct.get_commitment());
                pos += 1;
            }
            Some(cmt.get_root())
        } else {
            None
        }
    }
}

#[test]
fn sample_commitment_tree(){

    let zero = FieldElement::zero();
    let one = FieldElement::one();
    let two = FieldElement::one() + &FieldElement::one();

    // Empty db_path is not allowed
    assert!(CommitmentTree::create(&vec![two], "").is_err());

    // Empty list of SidechainTree (SCTs) IDs is not allowed
    assert!(CommitmentTree::create(&vec![], "./cmt_").is_err());

    // Duplicated SCT-IDs are not allowed
    assert!(CommitmentTree::create(&vec![two, one, two, zero], "./cmt_").is_err());

    let sc_ids = vec![two, one, zero];
    let non_existing_id = one + &two;

    let mut cmt = CommitmentTree::create(&sc_ids, "./cmt_").unwrap();

    // Check that SCTs are ordered by ID
    assert_eq!(vec![zero, one, two],
               cmt.sc_trees.iter().map(|sct| sct.id().to_owned()).collect::<Vec<FieldElement>>());

    // Commitment values of empty trees are different for a different SCTs due to dependence on SCT-IDs values.
    // So get initial commitment values of empty SCTs
    let empty_sc_comm: Vec<FieldElement> = sc_ids.iter()
        .flat_map(|sc_id| cmt.get_sc_commitment(sc_id)).collect();
    // Initial commitment value of an empty CMT
    let empty_comm = cmt.get_commitment().unwrap();

    // For each SCT-ID a correspondent SCT is created
    assert_eq!(empty_sc_comm.len(), sc_ids.len());

    // Initial commitment values of empty subtrees before updating them
    let empty_fwt_0  = cmt.get_fwt_commitment (&sc_ids[0]).unwrap();
    let empty_bwtr_0 = cmt.get_bwtr_commitment(&sc_ids[0]).unwrap();
    let empty_scc_1  = cmt.get_scc_commitment (&sc_ids[1]).unwrap();
    let empty_cert_1 = cmt.get_cert_commitment(&sc_ids[1]).unwrap();

    let fe = FieldElement::one();
    // Updating first SCT
    assert!(cmt.add_fwt (&sc_ids[0], &fe));
    assert!(cmt.add_bwtr(&sc_ids[0], &fe));
    // Updating second SCT
    assert!(cmt.add_scc (&sc_ids[1], &fe));
    assert!(cmt.add_cert(&sc_ids[1], &fe));
    // Updating third SCT
    assert!(cmt.add_csw (&sc_ids[2], &fe));

    // All updated subtrees should have non-empty commitment values
    assert_ne!(empty_fwt_0,  cmt.get_fwt_commitment (&sc_ids[0]).unwrap());
    assert_ne!(empty_bwtr_0, cmt.get_bwtr_commitment(&sc_ids[0]).unwrap());
    assert_ne!(empty_scc_1,  cmt.get_scc_commitment (&sc_ids[1]).unwrap());
    assert_ne!(empty_cert_1, cmt.get_cert_commitment(&sc_ids[1]).unwrap());

    // All updated SCTs should have non-empty commitment values
    sc_ids.iter().zip(empty_sc_comm)
        .for_each(
            |(sc_id, empty_comm)| {
                assert_ne!(cmt.get_sc_commitment(sc_id).unwrap(), empty_comm)
            });

    // No data can be added to a non-existing SCT
    assert!(!cmt.add_fwt (&non_existing_id, &fe));
    assert!(!cmt.add_bwtr(&non_existing_id, &fe));
    assert!(!cmt.add_scc (&non_existing_id, &fe));
    assert!(!cmt.add_cert(&non_existing_id, &fe));
    assert!(!cmt.add_csw (&non_existing_id, &fe));

    // There is no commitment for a non-existing SCT
    assert!(cmt.get_fwt_commitment (&non_existing_id).is_none());
    assert!(cmt.get_bwtr_commitment(&non_existing_id).is_none());
    assert!(cmt.get_scc_commitment (&non_existing_id).is_none());
    assert!(cmt.get_cert_commitment(&non_existing_id).is_none());
    assert!(cmt.get_sc_commitment  (&non_existing_id).is_none());

    // Commitment of the updated CMT has non-empty value
    assert_ne!(empty_comm, cmt.get_commitment().unwrap());
}
