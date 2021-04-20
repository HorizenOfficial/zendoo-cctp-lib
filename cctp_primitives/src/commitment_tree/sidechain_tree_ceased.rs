use crate::commitment_tree::{FieldElement, FieldElementsMT};
use crate::commitment_tree::utils::{pow2, hash_vec, new_mt, add_leaf, Error};
use std::borrow::BorrowMut;
use primitives::FieldBasedMerkleTree;

// Tunable parameters
pub const CSW_MT_HEIGHT: usize = 12;
const CSW_MT_CAPACITY:   usize = pow2(CSW_MT_HEIGHT);

pub struct SidechainTreeCeased{
    sc_id:  FieldElement,     // ID of a sidechain for which SidechainTree is created
    csw_mt: FieldElementsMT,  // MT for Ceased Sidechain Withdrawals
    csw_num: usize            // Number of contained Ceased Sidechain Withdrawals
}

impl SidechainTreeCeased{

    // Creates a new instance of SidechainTree with a specified ID
    pub fn create(sc_id: &FieldElement) -> Result<Self, Error> {
        Ok(
            Self{
                sc_id:   (*sc_id).clone(),
                csw_mt:  new_mt(CSW_MT_HEIGHT)?,
                csw_num: 0
            }
        )
    }

    // Gets ID of a SidechainTreeCeased
    pub fn id(&self) -> &FieldElement { &self.sc_id }

    // Sequentially adds leafs to the CSW MT
    pub fn add_csw(&mut self, csw: &FieldElement) -> bool {
        add_leaf(&mut self.csw_mt, csw, &mut self.csw_num, CSW_MT_CAPACITY)
    }

    // Gets commitment of the Ceased Sidechain Withdrawals tree
    pub fn get_csw_commitment(&mut self) -> FieldElement {
        self.csw_mt.borrow_mut().finalize().root().unwrap()
    }

    // Gets commitment of a SidechainTreeCeased
    pub fn get_commitment(&mut self) -> FieldElement {
        SidechainTreeCeased::build_commitment(
            self.sc_id,
            self.get_csw_commitment()
        )
    }

    // Builds commitment for SidechainTreeCeased as: hash( csw_root | SC_ID )
    pub fn build_commitment(sc_id: FieldElement,
                            csw_mr: FieldElement) -> FieldElement {
        hash_vec(&vec![csw_mr, sc_id])
    }
}

#[cfg(test)]
mod test {
    use algebra::Field;
    use crate::commitment_tree::FieldElement;
    use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;

    #[test]
    fn sidechain_tree_ceased_tests(){
        let sc_id = FieldElement::one();
        let mut sctc = SidechainTreeCeased::create(&sc_id).unwrap();

        // Initial commitment values of empty subtrees before updating them
        let empty_csw = sctc.get_csw_commitment();
        // Initial commitment value of an empty SCTC
        let empty_comm = sctc.get_commitment();

        let fe = FieldElement::one();
        // Updating subtree
        sctc.add_csw (&fe);

        // // An updated subtree should have non-empty commitment value
        assert_ne!(empty_csw, sctc.get_csw_commitment());
        // SCTC commitment has non-empty value
        assert_ne!(empty_comm, sctc.get_commitment());
    }
}
