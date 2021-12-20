use crate::type_mapping::{Error, FieldElement, GingerMHT};
use crate::utils::commitment_tree::{add_leaf, hash_vec, new_mt};
use primitives::FieldBasedMerkleTree;

// Tunable parameters
pub const CSW_MT_HEIGHT: usize = 12;

pub struct SidechainTreeCeased {
    sc_id: FieldElement, // ID of a sidechain for which SidechainTree is created
    csw_mt: GingerMHT,   // MT for Ceased Sidechain Withdrawals
}

impl SidechainTreeCeased {
    // Creates a new instance of SidechainTree with a specified ID
    pub fn create(sc_id: &FieldElement) -> Result<Self, Error> {
        Ok(Self {
            sc_id: (*sc_id).clone(),
            csw_mt: new_mt(CSW_MT_HEIGHT)?,
        })
    }

    // Gets ID of a SidechainTreeCeased
    pub fn id(&self) -> &FieldElement {
        &self.sc_id
    }

    // Sequentially adds leafs to the CSW MT
    pub fn add_csw(&mut self, csw: &FieldElement) -> bool {
        add_leaf(&mut self.csw_mt, csw)
    }

    // Gets commitment of the Ceased Sidechain Withdrawals tree
    pub fn get_csw_commitment(&mut self) -> Option<FieldElement> {
        match self.csw_mt.finalize() {
            Ok(finalized_tree) => finalized_tree.root(),
            Err(_) => None,
        }
    }

    // Gets commitment of a SidechainTreeCeased
    pub fn get_commitment(&mut self) -> Option<FieldElement> {
        SidechainTreeCeased::build_commitment(
            self.sc_id,
            match self.get_csw_commitment() {
                Some(v) => v,
                None => return None,
            },
        )
    }

    // Builds commitment for SidechainTreeCeased as: hash( csw_root | SC_ID )
    pub fn build_commitment(sc_id: FieldElement, csw_mr: FieldElement) -> Option<FieldElement> {
        match hash_vec(vec![csw_mr, sc_id]) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("{}", e);
                return None;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;
    use crate::type_mapping::FieldElement;
    use algebra::Field;

    #[test]
    fn sidechain_tree_ceased_tests() {
        let sc_id = FieldElement::one();
        let mut sctc = SidechainTreeCeased::create(&sc_id).unwrap();

        // Initial commitment values of empty subtrees before updating them
        let empty_csw = sctc.get_csw_commitment();
        // Initial commitment value of an empty SCTC
        let empty_comm = sctc.get_commitment();

        let fe = FieldElement::one();
        // Updating subtree
        sctc.add_csw(&fe);

        // // An updated subtree should have non-empty commitment value
        assert_ne!(empty_csw, sctc.get_csw_commitment());
        // SCTC commitment has non-empty value
        assert_ne!(empty_comm, sctc.get_commitment());
    }
}
