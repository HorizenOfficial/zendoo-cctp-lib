use crate::type_mapping::{FieldElement, GingerMHT, Error};
use crate::commitment_tree::utils::{pow2, hash_vec, new_mt, add_leaf};
use std::borrow::BorrowMut;
use primitives::FieldBasedMerkleTree;

// Tunable parameters
pub const CSW_SMT_HEIGHT: usize = 12;
const CSW_SMT_CAPACITY:   usize = pow2(CSW_SMT_HEIGHT);

pub struct SidechainTreeCeased{
    sc_id:   FieldElement,     // ID of a sidechain for which SidechainTree is created
    csw_smt: GingerMHT,  // SMT for Ceased Sidechain Withdrawals
    csw_num: usize             // Number of contained Ceased Sidechain Withdrawals
}

impl SidechainTreeCeased{

    // Creates a new instance of SidechainTree with a specified ID
    pub fn create(sc_id: &FieldElement) -> Result<SidechainTreeCeased, Error> {
        Ok(
            SidechainTreeCeased{
                sc_id:   (*sc_id).clone(),
                csw_smt: new_mt(CSW_SMT_HEIGHT)?,
                csw_num: 0
            }
        )
    }

    // Gets ID of a SidechainTreeCeased
    pub fn id(&self) -> &FieldElement { &self.sc_id }

    // Sequentially adds leafs to the CSW SMT
    pub fn add_csw(&mut self, csw: &FieldElement) -> bool {
        // add_leaf(&mut self.csw_smt, csw, &mut self.csw_num, CSW_SMT_CAPACITY)
        add_leaf(&mut self.csw_smt, csw, &mut self.csw_num, CSW_SMT_CAPACITY)
    }

    // Gets commitment_tree of the Ceased Sidechain Withdrawals tree
    pub fn get_csw_commitment(&mut self) -> FieldElement {
        self.csw_smt.borrow_mut().finalize().root().unwrap()
    }

    // Gets commitment_tree of a SidechainTree
    // Commitment = hash( csw_root | SC_ID )
    pub fn get_commitment(&mut self) -> FieldElement {
        let csw_mr = self.get_csw_commitment();
        hash_vec(&vec![csw_mr, self.sc_id])
    }
}

#[cfg(test)]
mod test {
    use algebra::Field;
    use crate::type_mapping::FieldElement;
    use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;

    #[test]
    fn sidechain_tree_ceased_tests(){
        let sc_id = FieldElement::one();
        let mut sctc = SidechainTreeCeased::create(&sc_id).unwrap();

        // Initial commitment_tree values of empty subtrees before updating them
        let empty_csw = sctc.get_csw_commitment();
        // Initial commitment_tree value of an empty SCTC
        let empty_comm = sctc.get_commitment();

        let fe = FieldElement::one();
        // Updating subtree
        sctc.add_csw (&fe);

        // // An updated subtree should have non-empty commitment_tree value
        assert_ne!(empty_csw, sctc.get_csw_commitment());
        // SCTC commitment_tree has non-empty value
        assert_ne!(empty_comm, sctc.get_commitment());
    }
}
