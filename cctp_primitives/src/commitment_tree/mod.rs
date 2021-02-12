use primitives::{
    merkle_tree::field_based_mht::{
        smt::{BigMerkleTree, Coord},
        poseidon::MNT4753_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS,
        FieldBasedMerkleTreeParameters
    }, MNT4PoseidonHash, FieldBasedMerkleTreePrecomputedEmptyConstants
};
use algebra::{fields::mnt4753::Fr, Field};
use crate::commitment_tree::sidechain_tree::{SidechainTree, SidechainSubtreeType};
use crate::commitment_tree::utils::{pow2, new_smt, Error};
use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;

pub mod sidechain_tree;
pub mod sidechain_tree_ceased;
pub mod utils;

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

// Tunable parameters
const CMT_SMT_HEIGHT:    usize = 12;
const CMT_SMT_CAPACITY:  usize = pow2(CMT_SMT_HEIGHT);
const CMT_PATH_SUFFIX:   &str = "_cmt";

pub struct CommitmentTree {
    sc_trees:           Vec<SidechainTree>,         // ordered by IDs list of Sidechain Trees
    sc_trees_ceased:    Vec<SidechainTreeCeased>,   // ordered by IDs list of Ceased Sidechain Trees
    base_path:          String                      // path for underlying SMT-based subtrees
}

impl CommitmentTree {

    // Creates new instance of a CommitmentTree
    // db_path - is a path to some not yet created directory; it is needed for underlying Sparse Merkle Trees.
    // NOTE: The last part of the db_path is used as a prefix of subdirectories name, i.e. for /tmp/cmt, the CMT's subdirectories will be placed in /tmp with their own directories names prefixed with 'cmt'
    pub fn create(db_path: &str) -> Result<CommitmentTree, Error> {
        if !db_path.is_empty(){
            Ok(
                CommitmentTree{
                    sc_trees: Vec::new(),
                    sc_trees_ceased: Vec::new(),
                    base_path: db_path.to_owned()
                }
            )
        } else {
            Err("Empty db_path".into())
        }
    }

    // Returns true if no more sidechain-trees can be added to a CommitmentTree
    fn is_full(&self) -> bool {
        (self.sc_trees.len() + self.sc_trees_ceased.len()) == CMT_SMT_CAPACITY
    }

    // Returns true if CommitmentTree contains SidechainTree with a specified ID
    fn is_present_sct(&self, sc_id: &FieldElement) -> bool {
        self.get_sct(sc_id).is_some()
    }

    // Returns true if CommitmentTree contains SidechainTreeCeased with a specified ID
    fn is_present_sctc(&self, sc_id: &FieldElement) -> bool {
        self.get_sctc(sc_id).is_some()
    }

    // Gets reference to a SidechainTree with a specified ID; If such a tree doesn't exist returns None
    fn get_sct(&self, sc_id: &FieldElement) -> Option<&SidechainTree> {
        self.sc_trees.iter().find(|sc| sc.id() == sc_id)
    }

    // Gets reference to a SidechainTreeCeased with a specified ID; If such a tree doesn't exist returns None
    fn get_sctc(&self, sc_id: &FieldElement) -> Option<&SidechainTreeCeased> {
        self.sc_trees_ceased.iter().find(|sc| sc.id() == sc_id)
    }

    // Adds an empty SidechainTree with a specified ID to a CommitmentTree
    // Returns mutable reference to a new SidechainTree or
    //         None if CommitmentTree is full or an error occurred during creation of a new SidechainTree
    fn add_sct(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTree> {
        if !self.is_full(){
            if let Ok(new_sct) = SidechainTree::create(&sc_id, &self.base_path){
                self.sc_trees.push(new_sct);
                self.sc_trees.last_mut()
            } else {
                None
            }
        } else {
            None
        }
    }

    // Adds an empty SidechainTreeCeased with a specified ID to a CommitmentTree
    // Returns mutable reference to a new SidechainTreeCeased or
    //         None if CommitmentTree is full or an error occurred during creation of a new SidechainTreeCeased
    fn add_sctc(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeCeased> {
        if !self.is_full(){ // Add new SidechainTreeCeased if there is free space in CommitmentTree
            if let Ok(new_sctc) = SidechainTreeCeased::create(&sc_id, &self.base_path) {
                self.sc_trees_ceased.push(new_sctc);
                self.sc_trees_ceased.last_mut()
            } else {
                None
            }
        } else {
            None
        }
    }

    // Gets mutable reference to a SidechainTree with a specified ID;
    // If such a SidechainTree doesn't exist adds new tree with a specified ID and returns mutable reference to it
    // Returns None if SidechainTree with a specified ID doesn't exist and can't be added
    fn get_sct_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTree> {
        if !self.is_present_sct(sc_id) { // Add new SidechainTree if there is free space
            self.add_sct(sc_id)
        } else {
            self.sc_trees.iter_mut().find(|sc_tree| sc_tree.id() == sc_id)
        }
    }

    // Gets mutable reference to a SidechainTreeCeased with a specified ID;
    // If such a SidechainTreeCeased doesn't exist adds new tree with a specified ID and returns mutable reference to it
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist and can't be added
    fn get_sctc_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeCeased> {
        if !self.is_present_sctc(sc_id) && !self.is_full() {
            self.add_sctc(sc_id)
        } else {
            self.sc_trees_ceased.iter_mut().find(|sc_tree| sc_tree.id() == sc_id)
        }
    }

    // Adds leaf to a subtree of a specified type in a specified SidechainTree
    // Returns false if there is SidechainTreeCeased with the same ID or if get_sct_mut couldn't get SidechainTree with a specified ID
    fn sct_add_subtree_leaf(&mut self, sc_id: &FieldElement, leaf: &FieldElement, subtree_type: SidechainSubtreeType) -> bool {
        if !self.is_present_sctc(sc_id) { // there shouldn't be SCTC with the same ID
            if let Some(sct) = self.get_sct_mut(sc_id){
                match subtree_type {
                    SidechainSubtreeType::FWT  => sct.add_fwt (leaf),
                    SidechainSubtreeType::BWTR => sct.add_bwtr(leaf),
                    SidechainSubtreeType::CERT => sct.add_cert(leaf),
                    SidechainSubtreeType::SCC  => { sct.set_scc(leaf); true }
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    // Adds leaf to a CSW-subtree of a specified SidechainTreeCeased
    // Returns false if there is SidechainTree with the same ID or if get_sctc_mut couldn't get SidechainTreeCeased with a specified ID
    fn sctc_add_subtree_leaf(&mut self, sc_id: &FieldElement, leaf: &FieldElement) -> bool {
        if !self.is_present_sct(sc_id) { // there shouldn't be SCT with the same ID
            if let Some(sctc) = self.get_sctc_mut(sc_id){
                sctc.add_csw(leaf)
            } else {
                false
            }
        } else {
            false
        }
    }

    // Gets commitment i.e. root of a subtree of a specified type in a specified SidechainTree
    // Returns None if get_sct couldn't get SidechainTree with a specified ID
    fn sct_get_subtree_commitment(&self, sc_id: &FieldElement, subtree_type: SidechainSubtreeType) -> Option<FieldElement> {
        if let Some(sc_tree) = self.get_sct(sc_id){
            Some(
                match subtree_type {
                    SidechainSubtreeType::FWT  => sc_tree.get_fwt_commitment(),
                    SidechainSubtreeType::BWTR => sc_tree.get_bwtr_commitment(),
                    SidechainSubtreeType::CERT => sc_tree.get_cert_commitment(),
                    SidechainSubtreeType::SCC  => panic!("There is no commitment for SCC")
                }
            )
        } else {
            None
        }
    }

    // Gets commitment i.e. root of a subtree of a specified type in a specified SidechainTreeCeased
    // Returns None if get_sctc couldn't get SidechainTreeCeased with a specified ID
    fn sctc_get_subtree_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        if let Some(sctc) = self.get_sctc(sc_id){
            Some(sctc.get_csw_commitment())
        } else {
            None
        }
    }

    // Adds Forward Transfer Transaction's hash to the FWT subtree of the corresponding SidechainTree
    // Returns false if FWT subtree has no place to add new element or if there is a SidechainTreeCeased with the specified ID
    pub fn add_fwt(&mut self, sc_id: &FieldElement, fwt: &FieldElement) -> bool {
        self.sct_add_subtree_leaf(sc_id, fwt, SidechainSubtreeType::FWT)
    }

    // Adds Backward Transfer Request Transaction's hash to the BWTR subtree of the corresponding SidechainTree
    // Returns false if BWTR subtree has no place to add new element or if there is a SidechainTreeCeased with the specified ID
    pub fn add_bwtr(&mut self, sc_id: &FieldElement, bwtr: &FieldElement) -> bool {
        self.sct_add_subtree_leaf(sc_id, bwtr, SidechainSubtreeType::BWTR)
    }

    // Adds Certificate's hash to the CERT subtree of the corresponding SidechainTree
    // Returns false if CERT subtree has no place to add new element or if there is a SidechainTreeCeased with the specified ID
    pub fn add_cert(&mut self, sc_id: &FieldElement, cert: &FieldElement) -> bool {
        self.sct_add_subtree_leaf(sc_id, cert, SidechainSubtreeType::CERT)
    }

    // Sets Sidechain Creation Transaction's hash for the corresponding SidechainTree
    // Returns false if there is a SidechainTreeCeased with the specified ID
    pub fn set_scc(&mut self, sc_id: &FieldElement, scc: &FieldElement) -> bool {
        self.sct_add_subtree_leaf(sc_id, scc, SidechainSubtreeType::SCC)
    }

    // Adds Sidechain Withdrawal's hash to the CSW subtree of the corresponding SidechainTreeCeased
    // Returns false if CSW subtree has no place to add new element or if there is a SidechainTree with the specified ID
    pub fn add_csw(&mut self, sc_id: &FieldElement, csw: &FieldElement) -> bool {
        self.sctc_add_subtree_leaf(sc_id, csw)
    }

    // Gets commitment, i.e. root of the Forward Transfer Transactions subtree of a specified SidechainTree
    // Returns None if SidechainTree with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_fwt_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.sct_get_subtree_commitment(sc_id, SidechainSubtreeType::FWT)
    }

    // Gets commitment, i.e. root of the Backward Transfer Requests Transactions subtree of a specified SidechainTree
    // Returns None if SidechainTree with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_bwtr_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.sct_get_subtree_commitment(sc_id, SidechainSubtreeType::BWTR)
    }

    // Gets commitment, i.e. root of the Certificates subtree of a specified SidechainTree
    // Returns None if SidechainTree with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_cert_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.sct_get_subtree_commitment(sc_id, SidechainSubtreeType::CERT)
    }

    // Gets commitment, i.e. root of the Ceased Sidechain Withdrawals subtree of a specified SidechainTree
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_csw_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.sctc_get_subtree_commitment(sc_id)
    }

    // Gets commitment of a specified SidechainTree/SidechainTreeCeased
    // Returns None if SidechainTree/SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_sc_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement> {
        if let Some(sct) = self.get_sct(sc_id){
            Some(sct.get_commitment())
        } else if let Some(sctc) = self.get_sctc(sc_id){
            Some(sctc.get_commitment())
        } else {
            None
        }
    }

    // Returns a list of commitments for all contained SCTs and SCTCs
    // Commitments are ordered correspondingly to lexicographically sorted IDs of their SCTs and SCTCs
    fn get_sorted_sc_commitments(&self) -> Vec<FieldElement> {
        // List of all SCTs and SCTCs (id, commitment)-pairs merged together
        let mut id_commit: Vec<(&FieldElement, FieldElement)> =
            self.sc_trees.iter().map(|sc| (sc.id(), sc.get_commitment())).chain(
                self.sc_trees_ceased.iter().map(|sc| (sc.id(), sc.get_commitment()))
            ).collect();

        // Sort (id, commitment)-pairs by id and return a list of commitments
        id_commit.sort_by_key(|id_commit| (*id_commit).0);
        id_commit.iter().map(|id_commit| (*id_commit).1).collect()
    }

    // Gets commitment for a CommitmentTree
    // Returns None in case if some error occurred during `new_smt` creation
    // Note: The commitment value is computed as a root of SMT with SCT-commitments leafs ordered by corresponding SCT-IDs
    pub fn get_commitment(&self) -> Option<FieldElement> {
        if let Ok(mut cmt) = new_smt(&(self.base_path.to_owned() + CMT_PATH_SUFFIX), CMT_SMT_HEIGHT){
            for (i, sc_commitment) in self.get_sorted_sc_commitments().iter().enumerate() {
                cmt.insert_leaf(Coord::new(0, i), *sc_commitment);
            }
            Some(cmt.get_root())
        } else {
            None
        }
    }
}

#[test]
fn commitment_tree_tests(){

    let zero  = FieldElement::zero();
    let one   = FieldElement::one();
    let two   = FieldElement::one() + &one;
    let three = FieldElement::one() + &two;

    // Empty db_path is not allowed
    assert!(CommitmentTree::create("").is_err());
    let mut cmt = CommitmentTree::create("./cmt_").unwrap();

    let sc_ids = vec![three, two, one, zero];
    let non_existing_id = FieldElement::one() + &three;

    // Initial commitment_tree value of an empty CMT
    let empty_comm = cmt.get_commitment().unwrap();

    // Initial SCT commitments are empty due to absence of such SCTs
    assert_eq!(cmt.get_fwt_commitment (&sc_ids[0]), None);
    assert_eq!(cmt.get_bwtr_commitment(&sc_ids[1]), None);
    assert_eq!(cmt.get_cert_commitment(&sc_ids[2]), None);
    assert_eq!(cmt.get_csw_commitment (&sc_ids[3]), None);

    let fe = FieldElement::one();
    // Set values in corresponding subtrees with transparent creation of the SCTs with specified IDs
    assert!(cmt.add_fwt (&sc_ids[0], &fe));
    assert!(cmt.add_bwtr(&sc_ids[1], &fe));
    assert!(cmt.add_cert(&sc_ids[2], &fe));
    assert!(cmt.add_csw (&sc_ids[3], &fe));

    // All updated subtrees should have non-empty subtrees roots
    assert!(cmt.get_fwt_commitment (&sc_ids[0]).is_some());
    assert!(cmt.get_bwtr_commitment(&sc_ids[1]).is_some());
    assert!(cmt.get_cert_commitment(&sc_ids[2]).is_some());
    assert!(cmt.get_csw_commitment (&sc_ids[3]).is_some());

    // All updated SCTs should have non-empty commitments
    sc_ids.iter().for_each(|sc_id|
        assert!(cmt.get_sc_commitment(sc_id).is_some())
    );

    // There is no SCT for ID which wasn't added during previous calls
    assert!(cmt.get_sc_commitment(&non_existing_id).is_none());

    // No CSW data can be added to any SCT
    assert!(!cmt.add_csw (&sc_ids[0], &fe));
    assert!(!cmt.add_csw (&sc_ids[1], &fe));
    assert!(!cmt.add_csw (&sc_ids[2], &fe));

    // No SCT-related data can be added to SCTC
    assert!(!cmt.add_fwt (&sc_ids[3], &fe));
    assert!(!cmt.add_bwtr(&sc_ids[3], &fe));
    assert!(!cmt.add_cert(&sc_ids[3], &fe));

    // Updating SCC in the first SCT and checking that commitment of this tree also has been updated
    let comm_without_scc = cmt.get_sc_commitment(&sc_ids[0]);
    cmt.set_scc(&sc_ids[0], &fe);
    assert_ne!(comm_without_scc, cmt.get_sc_commitment(&sc_ids[0]));

    // Commitment of the updated CMT has non-empty value
    assert_ne!(empty_comm, cmt.get_commitment().unwrap());
}
