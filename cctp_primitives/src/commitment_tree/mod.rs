use primitives::{
    FieldBasedMerkleTreePath, FieldBasedMerkleTree
};
use crate::{
    commitment_tree::{
        sidechain_tree_alive::{SidechainTreeAlive, SidechainAliveSubtreeType},
        sidechain_tree_ceased::SidechainTreeCeased,
        proofs::{ScExistenceProof, ScAbsenceProof, ScCommitmentData, ScNeighbour},
        hashers::{hash_fwt, hash_bwtr, hash_scc, hash_cert, hash_csw}
    },
    proving_system::ProvingSystem,
    type_mapping::*,
    utils::{
        commitment_tree::{pow2, new_mt},
        data_structures::{BitVectorElementsConfig, BackwardTransfer}
    },
};

pub mod sidechain_tree_alive;
pub mod sidechain_tree_ceased;
pub mod proofs;
pub mod hashers;

//--------------------------------------------------------------------------------------------------
// Commitment Tree
//--------------------------------------------------------------------------------------------------
// Tunable parameters
pub const CMT_MT_HEIGHT: usize = 12;
const CMT_MT_CAPACITY: usize = pow2(CMT_MT_HEIGHT);
const CMT_EMPTY_COMMITMENT: &FieldElement = &GINGER_MHT_POSEIDON_PARAMETERS.nodes[CMT_MT_HEIGHT];

pub struct CommitmentTree {
    alive_sc_trees:   Vec<SidechainTreeAlive>,   // list of Alive Sidechain Trees
    ceased_sc_trees:  Vec<SidechainTreeCeased>,  // list of Ceased Sidechain Trees
    commitments_tree: Option<GingerMHT>,   // cached Commitment-MT, which is recomputed in case of some changes in underlying Alive/Ceased Sidechain Trees
}

impl CommitmentTree {

    // Creates a new instance of CommitmentTree
    pub fn create() -> Self {
        Self{
            alive_sc_trees:   Vec::new(),
            ceased_sc_trees:  Vec::new(),
            commitments_tree: None
        }
    }

    // Adds Forward Transfer Transaction to the Commitment Tree
    // Returns false if hash_fwt can't get hash for data given in parameters;
    //         otherwise returns the same as add_fwt_leaf method
    pub fn add_fwt(
        &mut self,
        sc_id: &FieldElement,
        amount: u64,
        pub_key: &[u8; 32],
        tx_hash: &[u8; 32],
        out_idx: u32
    ) -> bool {
        if let Ok(fwt_leaf) = hash_fwt(
            amount, pub_key, tx_hash, out_idx
        ){
            self.add_fwt_leaf(sc_id, &fwt_leaf)
        } else {
            false
        }
    }

    // Adds Backward Transfer Request Transaction to the Commitment Tree
    // Returns false if hash_bwtr can't get hash for data given in parameters;
    //         otherwise returns the same as add_bwtr_leaf method
    pub fn add_bwtr(
        &mut self,
        sc_id: &FieldElement,
        sc_fee:  u64,
        sc_request_data: Vec<&FieldElement>,
        mc_destination_address: &[u8; MC_PK_SIZE],
        tx_hash: &[u8; 32],
        out_idx: u32
    ) -> bool {
        if let Ok(bwtr_leaf) = hash_bwtr(
            sc_fee, sc_request_data, mc_destination_address, tx_hash, out_idx
        ){
            self.add_bwtr_leaf(sc_id, &bwtr_leaf)
        } else {
            false
        }
    }

    // Adds Certificate to the Commitment Tree
    // Returns false if hash_cert can't get hash for data given in parameters;
    //         otherwise returns the same as add_cert_leaf method
    pub fn add_cert(
        &mut self,
        sc_id: &FieldElement,
        epoch_number: u32,
        quality: u64,
        bt_list: &[BackwardTransfer],
        custom_fields: Option<Vec<&FieldElement>>, //aka proof_data - includes custom_field_elements and bit_vectors merkle roots
        end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
        btr_fee: u64,
        ft_min_amount: u64
    )-> bool {
        if let Ok(cert_leaf) = hash_cert(
            epoch_number, quality, bt_list, custom_fields,
            end_cumulative_sc_tx_commitment_tree_root, btr_fee, ft_min_amount
        ){
            self.add_cert_leaf(sc_id, &cert_leaf)
        } else {
            false
        }
    }

    // Adds Sidechain Creation Transaction to the Commitment Tree
    // Returns false if hash_scc can't get hash for data given in parameters;
    //         otherwise returns the same as set_scc_leaf method
    pub fn add_scc(
        &mut self,
        sc_id: &FieldElement,
        amount: u64,
        pub_key: &[u8; 32],
        tx_hash: &[u8; 32],
        out_idx: u32,
        withdrawal_epoch_length: u32,
        cert_proving_system: ProvingSystem,
        csw_proving_system: Option<ProvingSystem>,
        mc_btr_request_data_length: u8,
        custom_field_elements_configs: &[u8],
        custom_bitvector_elements_configs: &[BitVectorElementsConfig],
        btr_fee: u64,
        ft_min_amount: u64,
        custom_creation_data: &[u8],
        constant: Option<&FieldElement>,
        cert_verification_key: &[u8],
        csw_verification_key: Option<&[u8]>
    )-> bool {
        if let Ok(scc_leaf) = hash_scc(
            amount, pub_key, tx_hash, out_idx, withdrawal_epoch_length, cert_proving_system,
            csw_proving_system, mc_btr_request_data_length, custom_field_elements_configs,
            custom_bitvector_elements_configs, btr_fee, ft_min_amount, custom_creation_data,
            constant, cert_verification_key, csw_verification_key
        ){
            self.set_scc(sc_id, &scc_leaf)
        } else {
            false
        }
    }

    // Adds Ceased Sidechain Withdrawal to the Commitment Tree
    // Returns false if hash_csw can't get hash for data given in parameters;
    //         otherwise returns the same as add_csw_leaf method
    pub fn add_csw(
        &mut self,
        sc_id:      &FieldElement,
        amount:     u64,
        nullifier:  &FieldElement,
        mc_pk_hash: &[u8; MC_PK_SIZE],
    )-> bool {
        if let Ok(csw_leaf) = hash_csw(
            amount, nullifier, mc_pk_hash
        ){
            self.add_csw_leaf(sc_id, &csw_leaf)
        } else {
            false
        }
    }

    // Adds Forward Transfer Transaction's hash to the FWT subtree of the corresponding SidechainTreeAlive
    // Returns false if maximum number of FWTs has been inserted or if there is a SidechainTreeCeased with the specified ID
    pub fn add_fwt_leaf(&mut self, sc_id: &FieldElement, fwt: &FieldElement) -> bool {
        self.scta_add_subtree_leaf(sc_id, fwt, SidechainAliveSubtreeType::FWT)
    }

    // Adds Backward Transfer Request Transaction's hash to the BWTR subtree of the corresponding SidechainTreeAlive
    // Returns false if maximum number of BWTRs has been inserted or if there is a SidechainTreeCeased with the specified ID
    pub fn add_bwtr_leaf(&mut self, sc_id: &FieldElement, bwtr: &FieldElement) -> bool {
        self.scta_add_subtree_leaf(sc_id, bwtr, SidechainAliveSubtreeType::BWTR)
    }

    // Adds Certificate's hash to the CERT subtree of the corresponding SidechainTreeAlive
    // Returns false if maximum number of CERTs has been inserted or if there is a SidechainTreeCeased with the specified ID
    pub fn add_cert_leaf(&mut self, sc_id: &FieldElement, cert: &FieldElement) -> bool {
        self.scta_add_subtree_leaf(sc_id, cert, SidechainAliveSubtreeType::CERT)
    }

    // Sets Sidechain Creation Transaction's hash for the corresponding SidechainTreeAlive
    // Returns false if there is a SidechainTreeCeased with the specified ID
    pub fn set_scc(&mut self, sc_id: &FieldElement, scc: &FieldElement) -> bool {
        self.scta_add_subtree_leaf(sc_id, scc, SidechainAliveSubtreeType::SCC)
    }

    // Adds Ceased Sidechain Withdrawal's hash to the CSW subtree of the corresponding SidechainTreeCeased
    // Returns false if CSW subtree has no place to add new element or if there is a SidechainTreeAlive with the specified ID
    pub fn add_csw_leaf(&mut self, sc_id: &FieldElement, csw: &FieldElement) -> bool {
        self.sctc_add_subtree_leaf(sc_id, csw)
    }

    // Gets commitment, i.e. root of the Forward Transfer Transactions subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeAlive with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_fwt_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.scta_get_subtree_commitment(sc_id, SidechainAliveSubtreeType::FWT)
    }

    // Gets commitment, i.e. root of the Backward Transfer Requests Transactions subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeAlive with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_bwtr_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.scta_get_subtree_commitment(sc_id, SidechainAliveSubtreeType::BWTR)
    }

    // Gets commitment, i.e. root of the Certificates subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeAlive with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_cert_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.scta_get_subtree_commitment(sc_id, SidechainAliveSubtreeType::CERT)
    }

    // Gets Sidechain Creation Transaction hash for a specified SidechainTreeAlive
    // Returns None if SidechainTreeAlive with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_scc(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.scta_get_subtree_commitment(sc_id, SidechainAliveSubtreeType::SCC)
    }

    // Gets commitment, i.e. root of the Ceased Sidechain Withdrawals subtree of a specified SidechainTreeCeased
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_csw_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.sctc_get_subtree_commitment(sc_id)
    }

    // Gets all leaves, of a Forward Transfer Transactions subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_fwt_leaves(&mut self, sc_id: &FieldElement) -> Option<Vec<FieldElement>> {
        self.scta_get_subtree_leaves(sc_id, SidechainAliveSubtreeType::FWT)
    }

    // Gets all leaves, of a Backward Transfer Requests Transactions subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_bwtr_leaves(&mut self, sc_id: &FieldElement) -> Option<Vec<FieldElement>> {
        self.scta_get_subtree_leaves(sc_id, SidechainAliveSubtreeType::BWTR)
    }

    // Gets all leaves, of a Certificates subtree of a specified SidechainTreeAlive
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_cert_leaves(&mut self, sc_id: &FieldElement) -> Option<Vec<FieldElement>> {
        self.scta_get_subtree_leaves(sc_id, SidechainAliveSubtreeType::CERT)
    }

    // Gets commitment of a specified SidechainTreeAlive/SidechainTreeCeased
    // Returns None if SidechainTreeAlive/SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    pub fn get_sc_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        self.get_sc_commitment_internal(sc_id)
    }

    // Gets commitment for a CommitmentTree
    // Returns None in case if some error occurred during `new_smt` creation
    // Note: The commitment value is computed as a root of MT with SCT-commitments leafs ordered by corresponding SCT-IDs
    pub fn get_commitment(&mut self) -> Option<FieldElement> {
        if let Some(cmt) = self.get_commitments_tree() {
            cmt.finalize().root()
        } else {
            None
        }
    }

    // Gets a proof of inclusion of a sidechain with specified ID into a current CommitmentTree
    // Returns None if sidechain with a specified ID is absent in a current CommitmentTree,
    //              if get_commitments_tree or get_merkle_path returned None
    pub fn get_sc_existence_proof(&mut self, sc_id: &FieldElement) -> Option<ScExistenceProof> {
        if let Some(index) = self.sc_id_to_index(sc_id){
            if let Some(tree) = self.get_commitments_tree(){
                Some(
                    ScExistenceProof::create(
                        tree.finalize().get_merkle_path(index)?
                    )
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    // Gets a proof of non-inclusion of a sidechain with specified ID into a current CommitmentTree
    // Returns None if absent_id_bytes are not a valid FieldElement serialization,
    //              if absent_id is not really absent,
    //              if some internal error occurred
    pub fn get_sc_absence_proof(&mut self, absent_id: &FieldElement) -> Option<ScAbsenceProof> {
        let (left, right) = self.get_neighbours_for_absent(absent_id)?;
        let tree = self.get_commitments_tree()?.finalize();

        let mut get_neighbour = |index_id: Option<(usize, FieldElement)>|{
            if let Some((index, id)) = index_id {
                Some(
                    ScNeighbour::create(
                        id,
                        tree.get_merkle_path(index)?,
                        self.get_sc_data(&id)?
                    )
                )
            } else {
                None
            }
        };
        Some(ScAbsenceProof::create(get_neighbour(left), get_neighbour(right)))
    }

    //----------------------------------------------------------------------------------------------
    // Static methods
    //----------------------------------------------------------------------------------------------

    // Verifies proof of sidechain inclusion into a specified CommitmentTree
    // Takes sidechain commitment, sidechain existence proof and a root of CommitmentTree - CMT-commitment
    // Returns true if proof is correct, false otherwise
    pub fn verify_sc_commitment(sc_commitment: &FieldElement, proof: &ScExistenceProof, commitment: &FieldElement) -> bool {
        if let Ok(res) = proof.mpath.verify(CMT_MT_HEIGHT, sc_commitment, commitment){
            res
        } else {
            false
        }
    }

    // Verifies proof of sidechain non-inclusion into a specified CommitmentTree
    // Takes sidechain ID, sidechain absence proof and a root of CommitmentTree - CMT-commitment
    // Returns true if proof is correct, false otherwise
    pub fn verify_sc_absence(absent_id: &FieldElement, proof: &ScAbsenceProof, commitment: &FieldElement) -> bool {
        // Checking if left and right neighbours are present
        if let (Some(left), Some(right)) = (
            proof.left.as_ref(), proof.right.as_ref()
        ){
            // Getting SC-commitments for the given SC-IDs
            if let (Some(left_sc_commitment),
                Some(right_sc_commitment)) = (
                left.sc_data.get_sc_commitment(&left.id),
                right.sc_data.get_sc_commitment(&right.id)
            ){
                // Validating Merkle Paths of SC-commitments
                let left_path_status = left.mpath.verify(CMT_MT_HEIGHT, &left_sc_commitment, commitment);
                let right_path_status = right.mpath.verify(CMT_MT_HEIGHT, &right_sc_commitment, commitment);

                // `left.id < right.id` is verified transitively with `left.id < absent_id && absent_id < right.id`
                &left.id < absent_id && absent_id < &right.id
                    && left_path_status.is_ok() && left_path_status.unwrap() == true
                    && right_path_status.is_ok() && right_path_status.unwrap() == true
                    && left.mpath.leaf_index() + 1 == right.mpath.leaf_index() // the smaller and bigger IDs have adjacent positions in MT
            } else {
                false // couldn't build sc_commitment
            }
        }
        // Checking if only left neighbour is present
        else if let Some(left) = proof.left.as_ref(){
            if let Some(left_sc_commitment) = left.sc_data.get_sc_commitment(&left.id) {
                let left_path_status = left.mpath.verify(CMT_MT_HEIGHT, &left_sc_commitment, commitment);

                &left.id < absent_id
                    && left_path_status.is_ok() && left_path_status.unwrap() == true
                    && (left.mpath.is_rightmost() || left.mpath.are_right_leaves_empty()) // is a last leaf in MT or a last non-empty leaf in MT
            } else {
                false // couldn't build sc_commitment
            }
        }
        // Checking if only right neighbour is present
        else if let Some(right) = proof.right.as_ref(){
            if let Some(right_sc_commitment) = right.sc_data.get_sc_commitment(&right.id) {
                let right_path_status = right.mpath.verify(CMT_MT_HEIGHT, &right_sc_commitment, commitment);

                absent_id < &right.id
                    && right_path_status.is_ok() && right_path_status.unwrap() == true
                    && right.mpath.is_leftmost() // the bigger ID is the smallest one in MT
            } else {
                false // couldn't build sc_commitment
            }
        }
        // Neither of neighbours is present
        else {
            // Empty proof is valid only for an empty CMT
            commitment == CMT_EMPTY_COMMITMENT
        }
    }

    //----------------------------------------------------------------------------------------------
    // Private auxiliary methods
    //----------------------------------------------------------------------------------------------

    // Returns true if no more sidechain-trees can be added to a CommitmentTree
    fn is_full(&self) -> bool {
        (self.alive_sc_trees.len() + self.ceased_sc_trees.len()) == CMT_MT_CAPACITY
    }

    // Returns true if CommitmentTree contains SidechainTreeAlive with a specified ID
    fn is_present_scta(&self, sc_id: &FieldElement) -> bool {
        self.get_scta(sc_id).is_some()
    }

    // Returns true if CommitmentTree contains SidechainTreeCeased with a specified ID
    fn is_present_sctc(&self, sc_id: &FieldElement) -> bool {
        self.get_sctc(sc_id).is_some()
    }

    // Gets reference to a SidechainTreeAlive with a specified ID; If such a tree doesn't exist returns None
    fn get_scta(&self, sc_id: &FieldElement) -> Option<&SidechainTreeAlive> {
        self.alive_sc_trees.iter().find(|sc| sc.id() == sc_id)
    }

    // Gets reference to a SidechainTreeCeased with a specified ID; If such a tree doesn't exist returns None
    fn get_sctc(&self, sc_id: &FieldElement) -> Option<&SidechainTreeCeased> {
        self.ceased_sc_trees.iter().find(|sc| sc.id() == sc_id)
    }
    // Gets mutable reference to a SidechainTreeCeased with a specified ID; If such a tree doesn't exist returns None
    fn get_sctc_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeCeased> {
        self.ceased_sc_trees.iter_mut().find(|sc_tree| sc_tree.id() == sc_id)
    }

    // Gets mutable reference to a SidechainTreeAlive with a specified ID; If such a tree doesn't exist returns None
    fn get_scta_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeAlive> {
        self.alive_sc_trees.iter_mut().find(|sc_tree| sc_tree.id() == sc_id)
    }

    // Adds an empty SidechainTreeAlive with a specified ID to a CommitmentTree
    // Returns mutable reference to a new SidechainTreeAlive or
    //         None if CommitmentTree is full or an error occurred during creation of a new SidechainTreeAlive
    fn add_scta(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeAlive> {
        if !self.is_full(){
            if let Ok(new_sct) = SidechainTreeAlive::create(&sc_id){
                self.alive_sc_trees.push(new_sct);
                self.alive_sc_trees.last_mut()
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
            if let Ok(new_sctc) = SidechainTreeCeased::create(&sc_id) {
                self.ceased_sc_trees.push(new_sctc);
                self.ceased_sc_trees.last_mut()
            } else {
                None
            }
        } else {
            None
        }
    }

    // Gets mutable reference to a SidechainTreeAlive with a specified ID;
    // If such a SidechainTreeAlive doesn't exist adds new tree with a specified ID and returns mutable reference to it
    // Returns None if SidechainTreeAlive with a specified ID doesn't exist and can't be added
    fn get_add_scta_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeAlive> {
        if self.is_present_scta(sc_id) { // Add new SidechainTreeAlive if there is free space
            self.get_scta_mut(sc_id)
        } else {
            self.add_scta(sc_id)
        }
    }

    // Gets mutable reference to a SidechainTreeCeased with a specified ID;
    // If such a SidechainTreeCeased doesn't exist adds new tree with a specified ID and returns mutable reference to it
    // Returns None if SidechainTreeCeased with a specified ID doesn't exist and can't be added
    fn get_add_sctc_mut(&mut self, sc_id: &FieldElement) -> Option<&mut SidechainTreeCeased> {
        if self.is_present_sctc(sc_id) && !self.is_full() {
            self.get_sctc_mut(sc_id)
        } else {
            self.add_sctc(sc_id)
        }
    }

    // Adds leaf to a subtree of a specified type in a specified SidechainTreeAlive
    // Returns false if there is SidechainTreeCeased with the same ID or if get_sct_mut couldn't get SidechainTreeAlive with a specified ID
    fn scta_add_subtree_leaf(&mut self, sc_id: &FieldElement, leaf: &FieldElement, subtree_type: SidechainAliveSubtreeType) -> bool {
        if !self.is_present_sctc(&sc_id) { // there shouldn't be SCTC with the same ID
            if let Some(sct) = self.get_add_scta_mut(sc_id){
                let result = match subtree_type {
                    SidechainAliveSubtreeType::FWT  => sct.add_fwt (leaf),
                    SidechainAliveSubtreeType::BWTR => sct.add_bwtr(leaf),
                    SidechainAliveSubtreeType::CERT => sct.add_cert(leaf),
                    SidechainAliveSubtreeType::SCC  => { sct.set_scc(leaf); true }
                };
                // If contents of the commitment tree has been updated then it should be rebuilt, so discard its current version
                if self.commitments_tree.is_some() && result == true { self.commitments_tree = None }
                result
            } else {
                false
            }
        } else {
            false
        }
    }

    // Adds leaf to a CSW-subtree of a specified SidechainTreeCeased
    // Returns false if there is SidechainTreeAlive with the same ID or if get_sctc_mut couldn't get SidechainTreeCeased with a specified ID
    fn sctc_add_subtree_leaf(&mut self, sc_id: &FieldElement, leaf: &FieldElement) -> bool {
        if !self.is_present_scta(sc_id) { // there shouldn't be SCTA with the same ID
            if let Some(sctc) = self.get_add_sctc_mut(&sc_id){
                let result = sctc.add_csw(leaf);
                // If contents of the commitment tree has been updated then it should be rebuilt, so discard its current version
                if self.commitments_tree.is_some() && result == true { self.commitments_tree = None }
                result
            } else {
                false
            }
        } else {
            false
        }
    }

    // Gets commitment i.e. root of a subtree of a specified type in a specified SidechainTreeAlive
    // Returns None if get_sctc couldn't get SidechainTreeCeased with a specified ID
    fn scta_get_subtree_commitment(&mut self, sc_id: &FieldElement, subtree_type: SidechainAliveSubtreeType) -> Option<FieldElement> {
        if let Some(sc_tree) = self.get_scta_mut(sc_id){
            Some(
                match subtree_type {
                    SidechainAliveSubtreeType::FWT  => sc_tree.get_fwt_commitment(),
                    SidechainAliveSubtreeType::BWTR => sc_tree.get_bwtr_commitment(),
                    SidechainAliveSubtreeType::CERT => sc_tree.get_cert_commitment(),
                    SidechainAliveSubtreeType::SCC  => sc_tree.get_scc() // just SCC value instead of commitment
                }
            )
        } else {
            None
        }
    }

    // Gets commitment i.e. root of a subtree of a specified type in a specified SidechainTreeCeased
    // Returns None if get_sctc couldn't get SidechainTreeCeased with a specified ID
    fn sctc_get_subtree_commitment(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        if let Some(sctc) = self.get_sctc_mut(sc_id){
            Some(sctc.get_csw_commitment())
        } else {
            None
        }
    }

    // Gets all leaves of a subtree of a specified type in a specified SidechainTreeAlive
    // Returns None if there is no SidechainTreeAlive with a specified ID
    fn scta_get_subtree_leaves(&mut self, sc_id: &FieldElement, subtree_type: SidechainAliveSubtreeType) -> Option<Vec<FieldElement>> {
        if let Some(sc_tree) = self.get_scta_mut(sc_id){
            Some(
                match subtree_type {
                    SidechainAliveSubtreeType::FWT  => sc_tree.get_fwt_leaves(),
                    SidechainAliveSubtreeType::BWTR => sc_tree.get_bwtr_leaves(),
                    SidechainAliveSubtreeType::CERT => sc_tree.get_cert_leaves(),
                    SidechainAliveSubtreeType::SCC  => panic!("There are no leaves for SCC")
                }
            )
        } else {
            None
        }
    }

    // Gets internal commitment-related data needed for building SC-Commitment for a specified by ID sidechain
    // Returns None if specified sidechain is not present in CommitmentTree
    fn get_sc_data(&mut self, sc_id: &FieldElement) -> Option<ScCommitmentData> {
        if let Some(sct) = self.get_scta_mut(sc_id){
            Some(
                ScCommitmentData::create_alive(
                    sct.get_fwt_commitment(),
                    sct.get_bwtr_commitment(),
                    sct.get_cert_commitment(),
                    sct.get_scc()
                )
            )
        } else if let Some(sctc) = self.get_sctc_mut(sc_id){
            Some(
                ScCommitmentData::create_ceased(
                    sctc.get_csw_commitment()
                )
            )
        } else {
            None
        }
    }

    // Gets commitment of a specified SidechainTreeAlive/SidechainTreeCeased
    // Returns None if SidechainTreeAlive/SidechainTreeCeased with a specified ID doesn't exist in a current CommitmentTree
    fn get_sc_commitment_internal(&mut self, sc_id: &FieldElement) -> Option<FieldElement> {
        if let Some(sct) = self.get_scta_mut(sc_id){
            Some(sct.get_commitment())
        } else if let Some(sctc) = self.get_sctc_mut(sc_id){
            Some(sctc.get_commitment())
        } else {
            None
        }
    }

    // Returns an indexed list of lexicographically ordered SC-IDs for all contained SCTAs and SCTCs
    fn get_indexed_sc_ids(&self) -> Vec<(usize, &FieldElement)> {
        // List of all SCTAs and SCTCs IDs merged together
        let mut ids: Vec<&FieldElement> = self.alive_sc_trees.iter().map(|sc| sc.id()).chain(
            self.ceased_sc_trees.iter().map(|sc| sc.id())
        ).collect();
        // Ordering IDs
        ids.sort();
        // Zip sorted IDs with indexes
        ids.into_iter().enumerate().collect()
    }

    // Build MT with ID-ordered SC-commitments as its leafs
    fn build_commitments_tree(&mut self) -> Option<GingerMHT> {
        let mut cmt = new_mt(CMT_MT_HEIGHT);
        let ids = self.get_indexed_sc_ids().into_iter().map(|s| *s.1).collect::<Vec<FieldElement>>();
        for id in ids {
            // SCTAs/SCTCs with such IDs exist, so unwrap() is safe here
            if cmt.append(self.get_sc_commitment_internal(&id).unwrap()).is_err() {
                return None;
            }
        }
        Some(cmt)
    }

    // Gets index of an MT leaf for a specified SC-ID
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

    // Gets a mutable reference to a current sc-commitments tree
    // Builds sc-commitments tree in case of its absence
    fn get_commitments_tree(&mut self) -> Option<&mut GingerMHT> {
        // build or rebuild a sidechain-commitments tree if there were updates of sc-subtrees
        if self.commitments_tree.is_none() {
            self.commitments_tree = self.build_commitments_tree()
        }
        self.commitments_tree.as_mut()
    }

    // For a given absent ID gets smaller and bigger neighbours in pair with their positions in a sorted list of existing SC-IDs
    // If absent ID is smaller then any of existing SC-IDs then a left neighbour is None
    // If absent ID is bigger then any of existing SC-IDs then a right neighbour is None
    // If there are no sidechains or a sidechain with a specified ID exists in a current CommitmentTree, returns (None, None)
    fn get_neighbours_for_absent(&self, absent_id: &FieldElement) -> Option<(Option<(usize, FieldElement)>, Option<(usize, FieldElement)>)> {
        let sc_ids = self.get_indexed_sc_ids();
        // Check that given ID is really absent in this list
        if sc_ids.iter().find(|(_, id)| *id == absent_id).is_none() {
            // Check that sidechains-IDs list is non-empty
            if !sc_ids.is_empty(){
                // Returns a tuple with a copy of SC-ID
                fn copy(index_idref: (usize, &FieldElement)) -> (usize, FieldElement){
                    (index_idref.0, *index_idref.1)
                }
                // Find a bigger neighbour of the absent_id
                let bigger_id = sc_ids.iter().find(|(_, id)| *id > absent_id);
                Some( // Return a pair of neighbours according to a relative position of absent_id in sorted SC-IDs list
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
                )
            } else {
                Some((None, None)) // return empty neighbours if there are no sidechains
            }
        } else {
            None // there are no neighbours for non-absent SC-ID
        }
    }
}

#[cfg(test)]
mod test {
    use algebra::{Field, test_canonical_serialize_deserialize};
    use crate::type_mapping::*;
    use crate::commitment_tree::CommitmentTree;
    use crate::utils::{
        data_structures::{BackwardTransfer, BitVectorElementsConfig},
        commitment_tree::{rand_vec, rand_fe, rand_fe_vec}
    };
    use crate::proving_system::ProvingSystem;
    use rand::Rng;
    use std::convert::TryInto;


    // Creates a sequence of FieldElements with values [0, 1, 2, 3, 4]
    fn get_fe_0_4() -> Vec<FieldElement>{
        let fe0 = FieldElement::zero();
        let fe1 = FieldElement::one();
        let fe2 = FieldElement::one() + fe1;
        let fe3 = FieldElement::one() + fe2;
        let fe4 = FieldElement::one() + fe3;
        vec![fe0, fe1, fe2, fe3, fe4]
    }

    #[test]
    fn commitment_tree_tests(){
        let mut cmt = CommitmentTree::create();
        let fe = get_fe_0_4();
        // Initial order of IDs is reversed, i.e. vec![3, 2, 1, 0] to test SCIDs-ordering functionality
        let sc_ids = fe.iter().take(4).rev().collect::<Vec<_>>();
        let non_existing_sc_id = &fe[4];

        // Initial commitment_tree value of an empty CMT
        let empty_comm = cmt.get_commitment().unwrap();

        // Initial SCT commitments are empty due to absence of such SCTs
        assert_eq!(cmt.get_fwt_commitment (sc_ids[0]), None);
        assert_eq!(cmt.get_bwtr_commitment(sc_ids[1]), None);
        assert_eq!(cmt.get_cert_commitment(sc_ids[2]), None);
        assert_eq!(cmt.get_csw_commitment (sc_ids[3]), None);

        // Set values in corresponding subtrees with transparent creation of the SCTs with specified IDs
        assert!(cmt.add_fwt_leaf(sc_ids[0], &fe[1]));
        assert!(cmt.add_bwtr_leaf(sc_ids[1], &fe[2]));
        assert!(cmt.add_cert_leaf(sc_ids[2], &fe[3]));
        assert!(cmt.add_csw_leaf(sc_ids[3], &fe[4]));

        // All updated subtrees should have the same leaves as what have been added
        assert_eq!(cmt.get_fwt_leaves(sc_ids[0]).unwrap(), vec![fe[1]]);
        assert_eq!(cmt.get_bwtr_leaves(sc_ids[1]).unwrap(), vec![fe[2]]);
        assert_eq!(cmt.get_cert_leaves(sc_ids[2]).unwrap(), vec![fe[3]]);

        // All non-updated subtrees should have empty list of leaves
        assert!(cmt.get_fwt_leaves(sc_ids[1]).unwrap().is_empty());
        assert!(cmt.get_bwtr_leaves(sc_ids[2]).unwrap().is_empty());
        assert!(cmt.get_cert_leaves(sc_ids[0]).unwrap().is_empty());

        // There should not be any leaves for nonexisting subtrees
        assert!(cmt.get_fwt_leaves(non_existing_sc_id).is_none());
        assert!(cmt.get_bwtr_leaves(non_existing_sc_id).is_none());
        assert!(cmt.get_cert_leaves(non_existing_sc_id).is_none());

        // All updated subtrees should have non-empty subtrees roots
        assert!(cmt.get_fwt_commitment (sc_ids[0]).is_some());
        assert!(cmt.get_bwtr_commitment(sc_ids[1]).is_some());
        assert!(cmt.get_cert_commitment(sc_ids[2]).is_some());
        assert!(cmt.get_csw_commitment (sc_ids[3]).is_some());

        // There should not be any roots for nonexisting subtrees
        assert!(cmt.get_fwt_commitment (non_existing_sc_id).is_none());
        assert!(cmt.get_bwtr_commitment(non_existing_sc_id).is_none());
        assert!(cmt.get_cert_commitment(non_existing_sc_id).is_none());
        assert!(cmt.get_csw_commitment (non_existing_sc_id).is_none());

        // All updated SCTs should have non-empty commitments
        sc_ids.clone().into_iter().for_each(|sc_id|
            assert!(cmt.get_sc_commitment(sc_id).is_some())
        );

        // There is no SCT for ID which wasn't added during previous calls
        assert!(cmt.get_sc_commitment(non_existing_sc_id).is_none());

        // No CSW data can be added to any SCT
        assert!(!cmt.add_csw_leaf(sc_ids[0], &fe[1]));
        assert!(!cmt.add_csw_leaf(sc_ids[1], &fe[1]));
        assert!(!cmt.add_csw_leaf(sc_ids[2], &fe[1]));

        // No SCT-related data can be added to SCTC
        assert!(!cmt.add_fwt_leaf(sc_ids[3], &fe[1]));
        assert!(!cmt.add_bwtr_leaf(sc_ids[3], &fe[1]));
        assert!(!cmt.add_cert_leaf(sc_ids[3], &fe[1]));

        // Updating SCC in the first SCT and checking that commitment of this tree also has been updated
        let comm_without_scc = cmt.get_sc_commitment(sc_ids[0]);
        cmt.set_scc(sc_ids[0], &fe[1]);
        assert_eq!(cmt.get_scc(sc_ids[0]).unwrap(), fe[1]);
        assert_ne!(comm_without_scc, cmt.get_sc_commitment(sc_ids[0]));

        // Commitment of the updated CMT has non-empty value
        assert_ne!(empty_comm, cmt.get_commitment().unwrap());

        // There is no existence-proof for a non-existing SC-ID
        assert!(cmt.get_sc_existence_proof(non_existing_sc_id).is_none());

        // Creating a valid existence proof
        let existence_proof = cmt.get_sc_existence_proof(sc_ids[0]);
        assert!(existence_proof.is_some());

        test_canonical_serialize_deserialize(true, &existence_proof);

        // Verification of a valid deserialized existence-proof
        assert!(CommitmentTree::verify_sc_commitment(
            cmt.get_sc_commitment(sc_ids[0]).as_ref().unwrap(),
            &existence_proof.unwrap(),
            cmt.get_commitment().as_ref().unwrap()));
    }

    #[test]
    fn sc_absence_proofs_tests(){
        let sc_id = get_fe_0_4().into_iter().collect::<Vec<_>>();

        let leaf = FieldElement::one();

        let mut cmt = CommitmentTree::create();

        // Getting commitment for empty CMT
        let commitment_empty = cmt.get_commitment();
        //------------------------------------------------------------------------------------------
        // Creating and validating absence proof in case of an empty CMT; Any SC-ID is absent in such a CMT
        let proof_empty = cmt.get_sc_absence_proof(&sc_id[0]);
        assert!(proof_empty.is_some());

        test_canonical_serialize_deserialize(true, &proof_empty);

        // Verification of a valid deserialized absence-proof
        assert!(CommitmentTree::verify_sc_absence(
            &sc_id[0],
            proof_empty.as_ref().unwrap(),
            commitment_empty.as_ref().unwrap())
        );

        //------------------------------------------------------------------------------------------
        // Initializing Commitment Tree
        // NOTE: Here index is the same as FieldElement-value of corresponding scId

        // Creating two SC-Trees with IDs: 1 and 3
        assert!(cmt.add_fwt_leaf(&sc_id[1], &leaf));
        assert!(cmt.add_csw_leaf(&sc_id[3], &leaf));

        // Getting commitment for all SC-trees
        let commitment = cmt.get_commitment();

        // There is no absence-proof for an existing SC-ID
        assert!(cmt.get_sc_absence_proof(&sc_id[1]).is_none());

        // Empty proof is not valid for a non-empty Commitment Tree
        assert!(!CommitmentTree::verify_sc_absence(
            &sc_id[0],
            proof_empty.as_ref().unwrap(),
            commitment.as_ref().unwrap())
        );
        //------------------------------------------------------------------------------------------
        // Creating and validating absence proof for non-existing ID which value is smaller than any existing ID
        let proof_leftmost = cmt.get_sc_absence_proof(&sc_id[0]);
        assert!(proof_leftmost.is_some());

        test_canonical_serialize_deserialize(true, &proof_leftmost);

        // Verification of a valid deserialized absence-proof
        assert!(CommitmentTree::verify_sc_absence(
            &sc_id[0],
            proof_leftmost.as_ref().unwrap(),
            commitment.as_ref().unwrap())
        );

        //------------------------------------------------------------------------------------------
        // Creating and validating absence proof for non-existing ID which value is between existing IDs
        let proof_midst = cmt.get_sc_absence_proof(&sc_id[2]);
        assert!(proof_midst.is_some());

        test_canonical_serialize_deserialize(true, &proof_midst);

        // Verification of a valid deserialized absence-proof
        assert!(CommitmentTree::verify_sc_absence(
            &sc_id[2],
            proof_midst.as_ref().unwrap(),
            commitment.as_ref().unwrap())
        );

        //------------------------------------------------------------------------------------------
        // Creating and validating absence proof for non-existing ID which value is bigger than any existing ID
        let proof_rightmost = cmt.get_sc_absence_proof(&sc_id[4]);
        assert!(proof_rightmost.is_some());

        test_canonical_serialize_deserialize(true, &proof_rightmost);

        // Verification of a valid deserialized absence-proof
        assert!(CommitmentTree::verify_sc_absence(
            &sc_id[4],
            proof_rightmost.as_ref().unwrap(),
            commitment.as_ref().unwrap())
        );
    }

    #[test]
    fn data_adding_tests(){
        let mut rng = rand::thread_rng();
        let mut cmt = CommitmentTree::create();

        let comm0 = cmt.get_commitment();

        assert!(
            cmt.add_fwt(
                &rand_fe(),
                rng.gen(),
                &rand_vec(32).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            )
        );

        // Checking that CommitmentTree is really updated
        let comm1 = cmt.get_commitment();
        assert_ne!(comm0, comm1);

        assert!(
            cmt.add_bwtr(
                &rand_fe(),
                rng.gen(),
                rand_fe_vec(10).iter().collect(),
                &rand_vec(MC_PK_SIZE).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen()
            )
        );

        let comm2 = cmt.get_commitment();
        assert_ne!(comm1, comm2);

        assert!(
            cmt.add_cert(
                &rand_fe(),
                rng.gen(),
                rng.gen(),
                &vec![BackwardTransfer::default(); 10],
                Some(rand_fe_vec(2).iter().collect()),
                &rand_fe(),
                rng.gen(),
                rng.gen(),
            )
        );

        let comm3 = cmt.get_commitment();
        assert_ne!(comm2, comm3);

        assert!(
            cmt.add_scc(
                &rand_fe(),
                rng.gen(),
                &rand_vec(32).try_into().unwrap(),
                &rand_vec(32).try_into().unwrap(),
                rng.gen(),
                rng.gen(),
                ProvingSystem::CoboundaryMarlin,
                Some(ProvingSystem::CoboundaryMarlin),
                rng.gen(),
                &rand_vec(10),
                &vec![BitVectorElementsConfig::default(); 10],
                rng.gen(),
                rng.gen(),
                &rand_vec(100),
                Some(&rand_fe()),
                &rand_vec(100),
                Some(&rand_vec(100))
            )
        );

        let comm4 = cmt.get_commitment();
        assert_ne!(comm3, comm4);

        assert!(
            cmt.add_csw(
                &rand_fe(),
                rng.gen(),
                &rand_fe(),
                &rand_vec(MC_PK_SIZE).try_into().unwrap()
            )
        );

        assert_ne!(comm4, cmt.get_commitment());
    }
}