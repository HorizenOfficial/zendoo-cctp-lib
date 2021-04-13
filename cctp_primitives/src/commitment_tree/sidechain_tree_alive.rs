use algebra::Field;
use crate::type_mapping::{FieldElement, GingerMHT};
use crate::commitment_tree::utils::{hash_vec, pow2, new_mt, add_leaf, Error};
use std::borrow::BorrowMut;
use primitives::FieldBasedMerkleTree;

// Tunable parameters
pub const FWT_SMT_HEIGHT:  usize = 12;
pub const BWTR_SMT_HEIGHT: usize = 12;
pub const CERT_SMT_HEIGHT: usize = 12;

const FWT_SMT_CAPACITY:  usize = pow2(FWT_SMT_HEIGHT);
const BWTR_SMT_CAPACITY: usize = pow2(BWTR_SMT_HEIGHT);
const CERT_SMT_CAPACITY: usize = pow2(CERT_SMT_HEIGHT);

// Types of contained subtrees
pub enum SidechainAliveSubtreeType {
    FWT, BWTR, CERT, SCC
}

pub struct SidechainTreeAlive {
    sc_id:    FieldElement,    // ID of a sidechain for which SidechainTreeAlive is created
    scc:      FieldElement,    // Sidechain Creation Transaction hash

    fwt_smt:  GingerMHT, // SMT for Forward Transfer Transactions
    bwtr_smt: GingerMHT, // SMT for Backward Transfers Requests Transactions
    cert_smt: GingerMHT, // SMT for Certificates

    fwt_num:  usize,           // Number of contained Forward Transfers Transactions
    bwtr_num: usize,           // Number of contained Backward Transfers Requests Transactions
    cert_num: usize,           // Number of contained Certificates
}

impl SidechainTreeAlive {

    // Creates a new instance of SidechainTreeAlive with a specified ID
    pub fn create(sc_id: &FieldElement) -> Result<SidechainTreeAlive, Error> {
        Ok(
            SidechainTreeAlive {
                sc_id:    (*sc_id).clone(),
                scc:      FieldElement::zero(),

                fwt_smt:  new_mt(FWT_SMT_HEIGHT)?,
                bwtr_smt: new_mt(BWTR_SMT_HEIGHT)?,
                cert_smt: new_mt(CERT_SMT_HEIGHT)?,

                fwt_num:  0,
                bwtr_num: 0,
                cert_num: 0
            }
        )
    }

    // Gets ID of a SidechainTreeAlive
    pub fn id(&self) -> &FieldElement { &self.sc_id }

    // Sequentially adds leafs to the FWT SMT
    pub fn add_fwt(&mut self, fwt: &FieldElement) -> bool {
        add_leaf(&mut self.fwt_smt, fwt, &mut self.fwt_num, FWT_SMT_CAPACITY)
    }

    // Sequentially adds leafs to the BWTR SMT
    pub fn add_bwtr(&mut self, bwtr: &FieldElement) -> bool {
        add_leaf(&mut self.bwtr_smt, bwtr, &mut self.bwtr_num, BWTR_SMT_CAPACITY)
    }

    // Sequentially adds leafs to the CERT SMT
    pub fn add_cert(&mut self, cert: &FieldElement) -> bool {
        add_leaf(&mut self.cert_smt, cert, &mut self.cert_num, CERT_SMT_CAPACITY)
    }

    // Sets SCC value
    pub fn set_scc(&mut self, scc: &FieldElement){ self.scc = *scc }

    // Gets SCC value
    pub fn get_scc(&self) -> FieldElement{ self.scc }

    // Gets all leaves of the FWT SMT
    pub fn get_fwt_leaves(&self) -> Vec<FieldElement> {
        self.fwt_smt.get_leaves().to_vec()
    }
    // Gets all leaves of the BWTR SMT
    pub fn get_bwtr_leaves(&self) -> Vec<FieldElement> {
        self.bwtr_smt.get_leaves().to_vec()
    }
    // Gets all leaves of the CERT SMT
    pub fn get_cert_leaves(&self) -> Vec<FieldElement> {
        self.cert_smt.get_leaves().to_vec()
    }

    // Gets commitment_tree of the Forward Transfer Transactions tree
    pub fn get_fwt_commitment(&mut self)  -> FieldElement { self.fwt_smt.borrow_mut().finalize().root().unwrap() }

    // Gets commitment_tree of the Backward Transfer Requests Transactions tree
    pub fn get_bwtr_commitment(&mut self) -> FieldElement { self.bwtr_smt.borrow_mut().finalize().root().unwrap() }

    // Gets commitment_tree of the Certificates tree
    pub fn get_cert_commitment(&mut self) -> FieldElement { self.cert_smt.borrow_mut().finalize().root().unwrap() }

    // Gets commitment_tree of a SidechainTreeAlive
    // Commitment = hash( fwt_root | bwtr_root | cert_root | SCC | SC_ID )
    pub fn get_commitment(&mut self) -> FieldElement {
        let fwt_mr  = self.get_fwt_commitment();
        let bwtr_mr = self.get_bwtr_commitment();
        let cert_mr = self.get_cert_commitment();

        hash_vec(&vec![fwt_mr, bwtr_mr, cert_mr, self.scc, self.sc_id])
    }
}

#[cfg(test)]
mod test {
    use crate::type_mapping::FieldElement;
    use algebra::Field;
    use crate::commitment_tree::sidechain_tree_alive::SidechainTreeAlive;

    #[test]
    fn sidechain_tree_tests(){
        let sc_id = FieldElement::one();

        let mut sct = SidechainTreeAlive::create(&sc_id).unwrap();

        // Initial commitment_tree values of empty subtrees before updating them
        let empty_fwt  = sct.get_fwt_commitment ();
        let empty_bwtr = sct.get_bwtr_commitment();
        let empty_cert = sct.get_cert_commitment();
        // Initial commitment_tree value of an empty SCT
        let empty_comm = sct.get_commitment();

        // All subtrees have the same initial commitment_tree value
        assert_eq!(empty_fwt, empty_bwtr);
        assert_eq!(empty_bwtr, empty_cert);

        let fe = FieldElement::one();
        // Updating subtrees
        sct.add_fwt (&fe);
        sct.add_bwtr(&fe);
        sct.add_cert(&fe);

        // The updated subtrees should have the same leaves as what have been added
        assert_eq!(sct.get_fwt_leaves(),  vec![fe]);
        assert_eq!(sct.get_bwtr_leaves(), vec![fe]);
        assert_eq!(sct.get_cert_leaves(), vec![fe]);

        // All updated subtrees should have non-empty commitment_tree values
        assert_ne!(empty_fwt,  sct.get_fwt_commitment ());
        assert_ne!(empty_bwtr, sct.get_bwtr_commitment());
        assert_ne!(empty_cert, sct.get_cert_commitment());

        // Updating SCC
        sct.set_scc(&fe);
        // Check that CSW is correctly updated
        assert_eq!(sct.get_scc(), fe);

        // SCT commitment_tree has non-empty value
        assert_ne!(empty_comm, sct.get_commitment());
    }
}
