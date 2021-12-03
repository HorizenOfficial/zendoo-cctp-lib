use crate::type_mapping::{Error, FieldElement, GingerMHT};
use crate::utils::commitment_tree::{add_leaf, hash_vec, new_mt};
use algebra::Group;
use primitives::FieldBasedMerkleTree;
use std::borrow::BorrowMut;

// Tunable parameters
pub const FWT_MT_HEIGHT: usize = 12;
pub const BWTR_MT_HEIGHT: usize = 12;
pub const CERT_MT_HEIGHT: usize = 12;

// Types of contained subtrees
pub enum SidechainAliveSubtreeType {
    FWT,
    BWTR,
    CERT,
    SCC,
}

pub struct SidechainTreeAlive {
    sc_id: FieldElement, // ID of a sidechain for which SidechainTreeAlive is created
    scc: FieldElement,   // Sidechain Creation Transaction hash

    fwt_mt: GingerMHT,  // MT for Forward Transfer Transactions
    bwtr_mt: GingerMHT, // MT for Backward Transfers Requests Transactions
    cert_mt: GingerMHT, // MT for Certificates
}

impl SidechainTreeAlive {
    // Creates a new instance of SidechainTreeAlive with a specified ID
    pub fn create(sc_id: &FieldElement) -> Result<Self, Error> {
        Ok(Self {
            sc_id: (*sc_id).clone(),

            // Default SCC value for an empty SidechainTreeAlive; Probability of collision with a real SCC value considering it is a random FieldElement is negligible
            scc: FieldElement::zero(),

            // Default leaves values of an empty GingerMHT are also FieldElement::zero(); They are specified in MHT_PARAMETERS as 0-level nodes
            fwt_mt: new_mt(FWT_MT_HEIGHT)?,
            bwtr_mt: new_mt(BWTR_MT_HEIGHT)?,
            cert_mt: new_mt(CERT_MT_HEIGHT)?,
        })
    }

    // Gets ID of a SidechainTreeAlive
    pub fn id(&self) -> &FieldElement {
        &self.sc_id
    }

    // Sequentially adds leafs to the FWT MT
    pub fn add_fwt(&mut self, fwt: &FieldElement) -> bool {
        add_leaf(&mut self.fwt_mt, fwt)
    }

    // Sequentially adds leafs to the BWTR MT
    pub fn add_bwtr(&mut self, bwtr: &FieldElement) -> bool {
        add_leaf(&mut self.bwtr_mt, bwtr)
    }

    // Sequentially adds leafs to the CERT MT
    pub fn add_cert(&mut self, cert: &FieldElement) -> bool {
        add_leaf(&mut self.cert_mt, cert)
    }

    // Sets SCC value
    pub fn set_scc(&mut self, scc: &FieldElement) {
        self.scc = *scc
    }

    // Gets SCC value
    pub fn get_scc(&self) -> FieldElement {
        self.scc
    }

    // Gets all leaves of the FWT MT
    pub fn get_fwt_leaves(&self) -> Vec<FieldElement> {
        self.fwt_mt.get_leaves().to_vec()
    }
    // Gets all leaves of the BWTR MT
    pub fn get_bwtr_leaves(&self) -> Vec<FieldElement> {
        self.bwtr_mt.get_leaves().to_vec()
    }
    // Gets all leaves of the CERT MT
    pub fn get_cert_leaves(&self) -> Vec<FieldElement> {
        self.cert_mt.get_leaves().to_vec()
    }

    // Gets commitment (root) of the Forward Transfer Transactions tree
    pub fn get_fwt_commitment(&mut self) -> Option<FieldElement> {
        match self.fwt_mt.borrow_mut().finalize() {
            Ok(finalized_tree) => finalized_tree.root(),
            Err(_) => None,
        }
    }

    // Gets commitment (root) of the Backward Transfer Requests Transactions tree
    pub fn get_bwtr_commitment(&mut self) -> Option<FieldElement> {
        match self.bwtr_mt.borrow_mut().finalize() {
            Ok(finalized_tree) => finalized_tree.root(),
            Err(_) => None,
        }
    }

    // Gets commitment (root) of the Certificates tree
    pub fn get_cert_commitment(&mut self) -> Option<FieldElement> {
        match self.cert_mt.borrow_mut().finalize() {
            Ok(finalized_tree) => finalized_tree.root(),
            Err(_) => None,
        }
    }

    // Gets commitment of a SidechainTreeAlive
    pub fn get_commitment(&mut self) -> Option<FieldElement> {
        SidechainTreeAlive::build_commitment(
            self.sc_id,
            match self.get_fwt_commitment() {
                Some(v) => v,
                None => return None,
            },
            match self.get_bwtr_commitment() {
                Some(v) => v,
                None => return None,
            },
            match self.get_cert_commitment() {
                Some(v) => v,
                None => return None,
            },
            self.scc,
        )
    }

    // Builds Commitment for SidechainTreeAlive as: hash( fwt_root | bwtr_root | cert_root | SCC | SC_ID )
    pub fn build_commitment(
        sc_id: FieldElement,
        fwt_mr: FieldElement,
        bwtr_mr: FieldElement,
        cert_mr: FieldElement,
        scc: FieldElement,
    ) -> Option<FieldElement> {
        match hash_vec(vec![fwt_mr, bwtr_mr, cert_mr, scc, sc_id]) {
            Ok(v) => Some(v),
            Err(e) => {
                eprint!("{}", e);
                return None;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::sidechain_tree_alive::SidechainTreeAlive;
    use crate::type_mapping::FieldElement;
    use algebra::Field;

    #[test]
    fn sidechain_tree_tests() {
        let sc_id = FieldElement::one();

        let mut sct = SidechainTreeAlive::create(&sc_id).unwrap();

        // Initial commitment values of empty subtrees before updating them
        let empty_fwt = sct.get_fwt_commitment();
        let empty_bwtr = sct.get_bwtr_commitment();
        let empty_cert = sct.get_cert_commitment();
        // Initial commitment value of an empty SCT
        let empty_comm = sct.get_commitment();

        // All subtrees have the same initial commitment value
        assert_eq!(empty_fwt, empty_bwtr);
        assert_eq!(empty_bwtr, empty_cert);

        let fe = FieldElement::one();
        // Updating subtrees
        sct.add_fwt(&fe);
        sct.add_bwtr(&fe);
        sct.add_cert(&fe);

        // The updated subtrees should have the same leaves as what have been added
        assert_eq!(sct.get_fwt_leaves(), vec![fe]);
        assert_eq!(sct.get_bwtr_leaves(), vec![fe]);
        assert_eq!(sct.get_cert_leaves(), vec![fe]);

        let updated_fwt = sct.get_fwt_commitment();
        let updated_bwtr = sct.get_bwtr_commitment();
        let updated_cert = sct.get_cert_commitment();

        // All updated subtrees should have non-empty commitment values
        assert_ne!(empty_fwt, updated_fwt);
        assert_ne!(empty_bwtr, updated_bwtr);
        assert_ne!(empty_cert, updated_cert);

        // All updated subtrees should have the same non-empty commitment value
        assert_eq!(updated_fwt, updated_bwtr);
        assert_eq!(updated_bwtr, updated_cert);

        // Updating SCC
        sct.set_scc(&fe);
        // Check that CSW is correctly updated
        assert_eq!(sct.get_scc(), fe);

        // SCT commitment has non-empty value
        assert_ne!(empty_comm, sct.get_commitment());
    }
}
