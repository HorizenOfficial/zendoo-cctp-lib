use primitives::{merkle_tree::field_based_mht::{
    smt::{BigMerkleTree, Coord},
    poseidon::MNT4753_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS,
    FieldBasedMerkleTreeParameters
}, MNT4PoseidonHash, FieldBasedMerkleTreePrecomputedEmptyConstants, FieldBasedBinaryMHTPath, FieldBasedMerkleTreePath};
use algebra::fields::mnt4753::Fr;
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

// Proof of existence of some SidechainTree/SidechainTreeCeased inside of a CommitmentTree;
// Actually it is a Merkle Path of SidechainTree/SidechainTreeCeased in a CommitmentTree
pub struct ScExistenceProof{
    mpath: FieldBasedBinaryMHTPath<GingerMerkleTreeParameters>
}
// Proof of absence of some Sidechain-ID inside of a CommitmentTree;
// Contains one or two neighbours of an absent ID
pub struct ScAbsenceProof{
    left:  Option<(FieldElement, FieldBasedBinaryMHTPath<GingerMerkleTreeParameters>)>, // a smaller ID of an existing SC together with Merkle Path of its SC-commitment
    right: Option<(FieldElement, FieldBasedBinaryMHTPath<GingerMerkleTreeParameters>)>  // a bigger ID of an existing SC together with Merkle Path of its SC-commitment
}

pub struct CommitmentTree {
    sc_trees:           Vec<SidechainTree>,         // ordered by IDs list of Sidechain Trees
    sc_trees_ceased:    Vec<SidechainTreeCeased>,   // ordered by IDs list of Ceased Sidechain Trees

    base_path:          String,                     // path for underlying SMT-based subtrees

    commitments_tree:   Option<FieldElementsSMT>,   // cached commitment SMT, which is recomputed if some changes in underlying Sidechain/Ceased Sidechain Trees occurred
    is_updated:         bool                        // true if underlying Sidechain/Ceased Sidechain Trees have been changed since the commitments_tree was built
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
                    base_path: db_path.to_owned(),
                    commitments_tree: None,
                    is_updated: false
                }
            )
        } else {
            Err("Empty db_path".into())
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

    // Gets commitment for a CommitmentTree
    // Returns None in case if some error occurred during `new_smt` creation
    // Note: The commitment value is computed as a root of SMT with SCT-commitments leafs ordered by corresponding SCT-IDs
    pub fn get_commitment(&mut self) -> Option<FieldElement> {
        if let Some(cmt) = self.get_commitments_tree() {
            Some(cmt.get_root())
        } else {
            None
        }
    }

    // Gets a proof of inclusion of a sidechain with specified ID into a current CommitmentTree
    // Returns None if sidechain with a specified ID is absent in a current CommitmentTree
    pub fn get_sc_existence_proof(&mut self, sc_id: &FieldElement) -> Option<ScExistenceProof> {
        if let Some(index) = self.sc_id_to_index(sc_id){
            if let Some(tree) = self.get_commitments_tree(){
                Some(ScExistenceProof{mpath: tree.get_merkle_path(Coord::new(0, index))})
            } else {
                None
            }
        } else {
            None
        }
    }

    // Gets a proof of non-inclusion of a sidechain with specified ID into a current CommitmentTree
    // Returns None if get_neighbours didn't return any neighbour for a specified ID
    pub fn get_sc_absence_proof(&mut self, absent_id: &FieldElement) -> Option<ScAbsenceProof> {
        let (left, right) = self.get_neighbours_for_absent(absent_id);
        if left.is_some() || right.is_some(){
            if let Some(tree) = self.get_commitments_tree(){
                Some(
                    ScAbsenceProof{
                        left: if let Some((index, left_id)) = left {
                            Some((left_id, tree.get_merkle_path(Coord::new(0, index))) )
                        } else { None },
                        right: if let Some((index, right_id)) = right {
                            Some((right_id, tree.get_merkle_path(Coord::new(0, index))) )
                        } else { None }
                    }
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    //----------------------------------------------------------------------------------------------
    // Static methods
    //----------------------------------------------------------------------------------------------

    // Verifies proof of sidechain inclusion into a specified CommitmentTree
    // Takes sidechain commitment, sidechain existence proof and a root of CommitmentTree - CMT-commitment
    // Returns true if proof is correct, false otherwise
    pub fn verify_sc_commitment(sc_commitment: &FieldElement, proof: &ScExistenceProof, commitment: &FieldElement) -> bool {
        if let Ok(res) = proof.mpath.verify(CMT_SMT_HEIGHT, sc_commitment, commitment){
            res
        } else {
            false
        }
    }

    // TODO: This method is supposed to be static but it needs to get SC-commitment for any existing SC-ID from the proof
    // So now it is non-static to have access to get_sc_commitment method;
    // To make it static the corresponding SC-commitments should be passed as parameters or included into the proof and verified in some way for consistency with SC-IDs from the proof
    //
    // Verifies proof of sidechain non-inclusion into a specified CommitmentTree
    // Takes sidechain ID, sidechain absence proof and a root of CommitmentTree - CMT-commitment
    // Returns true if proof is correct, false otherwise
    pub fn verify_sc_absence(&self, absent_id: &FieldElement, proof: &ScAbsenceProof, commitment: &FieldElement) -> bool {
        if proof.left.is_some() && proof.right.is_some(){
            let (left_id, left_mpath) = proof.left.as_ref().unwrap();
            let (right_id, right_mpath) = proof.right.as_ref().unwrap();

            // Validating Merkle Paths of SC-commitments for the given SC-IDs
            let left_path_status = left_mpath.verify(CMT_SMT_HEIGHT, &self.get_sc_commitment(left_id).unwrap(), commitment);
            let right_path_status = right_mpath.verify(CMT_SMT_HEIGHT, &self.get_sc_commitment(right_id).unwrap(), commitment);

            left_id < right_id
                && left_id < absent_id && absent_id < right_id
                && left_path_status.is_ok() && left_path_status.unwrap() == true
                && right_path_status.is_ok() && right_path_status.unwrap() == true
                && left_mpath.leaf_index() + 1 == right_mpath.leaf_index() // the smaller and bigger IDs have adjacent positions in SMT

        } else if proof.left.is_some() {
            let (left_id, left_mpath) = proof.left.as_ref().unwrap();
            let left_path_status = left_mpath.verify(CMT_SMT_HEIGHT, &self.get_sc_commitment(left_id).unwrap(), commitment);

            left_id < absent_id
                && left_path_status.is_ok() && left_path_status.unwrap() == true
                && (left_mpath.is_rightmost() || left_mpath.is_non_empty_rightmost()) // is a last leaf in SMT or a last non-empty leaf in SMT

        } else if proof.right.is_some() {
            let (right_id, right_mpath) = proof.right.as_ref().unwrap();
            let right_path_status = right_mpath.verify(CMT_SMT_HEIGHT, &self.get_sc_commitment(right_id).unwrap(), commitment);

            absent_id < right_id
                && right_path_status.is_ok() && right_path_status.unwrap() == true
                && right_mpath.is_leftmost() // the bigger ID is the smallest one in SMT

        } else {
            panic!("Left and Right IDs can't be absent together in ScAbsenceProof")
        }
    }

    //----------------------------------------------------------------------------------------------
    // Private auxiliary methods
    //----------------------------------------------------------------------------------------------

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
                let result = match subtree_type {
                    SidechainSubtreeType::FWT  => sct.add_fwt (leaf),
                    SidechainSubtreeType::BWTR => sct.add_bwtr(leaf),
                    SidechainSubtreeType::CERT => sct.add_cert(leaf),
                    SidechainSubtreeType::SCC  => { sct.set_scc(leaf); true }
                };
                if !self.is_updated { self.is_updated = result }
                result
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
                let result = sctc.add_csw(leaf);
                if !self.is_updated { self.is_updated = result }
                result
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

    // Returns an indexed list of lexicographically ordered SC-IDs for all contained SCTs and SCTCs
    fn get_indexed_sc_ids(&self) -> Vec<(usize, &FieldElement)> {
        // List of all SCTs and SCTCs IDs merged together
        let mut ids: Vec<&FieldElement> = self.sc_trees.iter().map(|sc| sc.id()).chain(
            self.sc_trees_ceased.iter().map(|sc| sc.id())
        ).collect();
        // Ordering IDs
        ids.sort();
        // Zip sorted IDs with indexes
        ids.into_iter().enumerate().collect()
    }

    // Build SMT with ID-ordered SC-commitments as its leafs
    fn build_commitments_tree(&self) -> Option<FieldElementsSMT> {
        if let Ok(mut cmt) = new_smt(&(self.base_path.to_owned() + CMT_PATH_SUFFIX), CMT_SMT_HEIGHT){
            for (i, id) in self.get_indexed_sc_ids().into_iter() {
                cmt.insert_leaf(Coord::new(0, i), self.get_sc_commitment(id).unwrap()); // SCTs/SCTCs with such IDs exist, so unwrap() is safe here
            }
            Some(cmt)
        } else {
            None
        }
    }

    // Gets index of an SMT leaf for a specified SC-ID
    // Returns None if sidechain with a specified ID is absent in a current CommitmentTree
    // NOTE: index is a position of the SC-ID inside of a sorted SC-IDs list
    fn sc_id_to_index(&mut self, sc_id: &FieldElement) -> Option<usize> {
        if let Some(i_id) = self.get_indexed_sc_ids().iter()
            .find(|(_, id)| sc_id == *id){
            Some(i_id.0)
        } else {
            None
        }
    }

    // Gets a mutable reference ot a current sc-commitments tree
    // Builds sc-commitments tree in case of its absence
    // Rebuilds sc-commitments tree if something has changed since last build
    fn get_commitments_tree(&mut self) -> Option<&mut FieldElementsSMT> {
        // build or rebuild a sidechain-commitments tree if there were updates of sc-trees
        if self.commitments_tree.is_none() || self.is_updated {
            // println!("{}", if self.commitments_tree.is_none() {"Building"} else {"Rebuilding"});
            // triggering deletion of an existing tree to free used by an underlying SMT resources such as FS-directories
            if self.commitments_tree.is_some() { self.commitments_tree = None }
            self.commitments_tree = self.build_commitments_tree();
            self.is_updated = false
        }
        self.commitments_tree.as_mut()
    }

    // For a given absent ID gets smaller and bigger neighbours in pair with their positions in a sorted list of existing SC-IDs
    // If absent ID is smaller then any of existing SC-IDs then a left neighbour is None
    // If absent ID is bigger then any of existing SC-IDs then a right neighbour is None
    // If there are no sidechains or a sidechain with a specified ID exists in a current CommitmentTree, returns (None, None)
    fn get_neighbours_for_absent(&self, absent_id: &FieldElement) -> (Option<(usize, FieldElement)>, Option<(usize, FieldElement)>) {
        let sc_ids = self.get_indexed_sc_ids();
        // Check that sidechains-IDs list is non-empty and the given ID is really absent in this list
        if !sc_ids.is_empty() &&
            sc_ids.iter().find(|(_, id)| *id == absent_id).is_none(){
            // Returns a tuple with a copy of SC-ID
            fn copy(index_idref: (usize, &FieldElement)) -> (usize, FieldElement){
                (index_idref.0, *index_idref.1)
            }
            // Find a bigger neighbour of the absent_id
            let bigger_id = sc_ids.iter().find(|(_, id)| *id > absent_id);
            if bigger_id.is_none(){
                // There is no bigger neighbour, so the last, i.e. the biggest existing SC-ID is the lesser neighbour
                (Some(copy(sc_ids[sc_ids.len() - 1])), None)
            } else {
                let right = bigger_id.unwrap().to_owned();
                let right_index = right.0;
                if right_index == 0 {
                    // There is no lesser neighbour, so the first i.e. the smallest existing SC-ID is the bigger neighbour
                    (None, Some(copy(right)))
                } else {
                    // The lesser neighbour is the previous one
                    (Some(copy(sc_ids[right_index - 1])), Some(copy(right)))
                }
            }
        } else {
            (None, None)
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

    // There is no existence-proof for a non-existing SC-ID
    assert!(cmt.get_sc_existence_proof(&non_existing_id).is_none());

    // Verification of a valid existence-proof
    assert!(CommitmentTree::verify_sc_commitment(
        cmt.get_sc_commitment(&sc_ids[0]).as_ref().unwrap(),
        cmt.get_sc_existence_proof(&sc_ids[0]).as_ref().unwrap(),
        cmt.get_commitment().as_ref().unwrap()));
}

#[test]
fn sc_absence_proofs_tests(){
    let zero  = FieldElement::zero();
    let one   = FieldElement::one();
    let two   = FieldElement::one() + &one;
    let three = FieldElement::one() + &two;
    let four  = FieldElement::one() + &three;

    let mut cmt = CommitmentTree::create("./cmt_").unwrap();

    // There is no absence-proof for an empty CommitmentTree
    assert!(cmt.get_sc_absence_proof(&one).is_none());

    let fe = FieldElement::one();

    // Creating two SC-Trees with IDs: 1 and 3
    cmt.add_fwt(&one, &fe);
    cmt.add_csw(&three, &fe);

    // Getting commitment for all SC-trees
    let commitment = cmt.get_commitment();

    // There is no absence-proof for an existing SC-ID
    assert!(cmt.get_sc_absence_proof(&one).is_none());

    // Creating and validating absence proof for non-existing ID which value is smaller of any existing IDs
    let proof_leftmost = cmt.get_sc_absence_proof(&zero);
    assert!(proof_leftmost.is_some());
    assert!(cmt.verify_sc_absence(
        &zero,
        proof_leftmost.as_ref().unwrap(),
        commitment.as_ref().unwrap())
    );

    // Creating and validating absence proof for non-existing ID which value is between existing IDs
    let proof_midst = cmt.get_sc_absence_proof(&two);
    assert!(proof_midst.is_some());
    assert!(cmt.verify_sc_absence(
        &two,
        proof_midst.as_ref().unwrap(),
        commitment.as_ref().unwrap())
    );

    // Creating and validating absence proof for non-existing ID which value is bigger of any existing IDs
    let proof_rightmost = cmt.get_sc_absence_proof(&four);
    assert!(proof_rightmost.is_some());
    assert!(cmt.verify_sc_absence(
        &four,
        proof_rightmost.as_ref().unwrap(),
        commitment.as_ref().unwrap())
    );
}
