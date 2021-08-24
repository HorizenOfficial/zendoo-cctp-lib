use crate::commitment_tree::sidechain_tree_alive::SidechainTreeAlive;
use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;
use crate::type_mapping::{FieldElement, GingerMHTPath};
use algebra::serialize::*;

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct ScAliveCommitmentData {
    fwt_mr: FieldElement,
    bwtr_mr: FieldElement,
    cert_mr: FieldElement,
    scc: FieldElement
}

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct ScCeasedCommitmentData {
    csw_mr: FieldElement
}

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScCommitmentData {
    sc_alive:  Option<ScAliveCommitmentData>,
    sc_ceased: Option<ScCeasedCommitmentData>
}

impl ScCommitmentData {
    pub(crate) fn create_alive(fwt_mr: FieldElement, bwtr_mr: FieldElement, cert_mr: FieldElement, scc: FieldElement) -> Self {
        Self{
            sc_alive: Some(
                ScAliveCommitmentData{ fwt_mr, bwtr_mr, cert_mr, scc }
            ),
            sc_ceased: None
        }
    }

    pub(crate) fn create_ceased(csw_mr: FieldElement) -> Self {
        Self{
            sc_alive: None,
            sc_ceased: Some(
                ScCeasedCommitmentData{ csw_mr }
            )
        }
    }

    // Builds Commitment of SidechainTreeAlive or SidechainTreeCeased for a specified SC-ID
    pub(crate) fn get_sc_commitment(&self, sc_id: &FieldElement) -> Option<FieldElement>{
        if self.sc_alive.is_some() && self.sc_ceased.is_some() {
            None // SC can be only one of two types: alive or ceased
        } else if let Some(data) = self.sc_alive.as_ref(){
            SidechainTreeAlive::build_commitment(*sc_id, data.fwt_mr, data.bwtr_mr, data.cert_mr, data.scc)
        } else if let Some(data) = self.sc_ceased.as_ref(){
            SidechainTreeCeased::build_commitment(*sc_id, data.csw_mr)
        } else {
            None // there is no data for commitment building
        }
    }
}

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScNeighbour{
    pub(crate) id:      FieldElement,    // ID of SC
    pub(crate) mpath:   GingerMHTPath,   // Merkle Path for SC-commitment of an SC with the given ID
    pub(crate) sc_data: ScCommitmentData // data needed to build SC-commitment for the given ID
}

impl ScNeighbour {
    pub(crate) fn create(id:      FieldElement,
                         mpath:   GingerMHTPath,
                         sc_data: ScCommitmentData) -> Self { Self{id, mpath, sc_data} }

}

//--------------------------------------------------------------------------------------------------
// Proof of absence of some Sidechain-ID inside of a CommitmentTree
// Contains 0 or 1 or 2 neighbours of an absent ID
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScAbsenceProof{
    pub(crate) left:  Option<ScNeighbour>, // neighbour with a smaller ID
    pub(crate) right: Option<ScNeighbour>  // neighbour with a bigger ID
}

impl ScAbsenceProof {
    pub(crate) fn create(left:  Option<ScNeighbour>, right: Option<ScNeighbour>) -> Self {
        Self{left, right}
    }
}

//--------------------------------------------------------------------------------------------------
// Proof of existence of some SidechainTreeAlive/SidechainTreeCeased inside of a CommitmentTree;
// Actually this is a Merkle Path of SidechainTreeAlive/SidechainTreeCeased inside of a CommitmentTree
#[derive(PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScExistenceProof{
    pub(crate) mpath: GingerMHTPath
}

impl ScExistenceProof {
    pub(crate) fn create(mpath: GingerMHTPath) -> Self {
        Self{ mpath }
    }
}

//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use crate::commitment_tree::proofs::{ScAliveCommitmentData, ScCeasedCommitmentData, ScCommitmentData, ScNeighbour};
    use crate::commitment_tree::CMT_MT_HEIGHT;
    use crate::utils::commitment_tree::new_mt;
    use crate::type_mapping::FieldElement;
    use algebra::{UniformRand, test_canonical_serialize_deserialize};
    use primitives::FieldBasedMerkleTree;

    // NOTE: Tests for ScExistenceProof and ScAbsenceProof are inside of the CommitmentTree module

    #[test]
    fn test_sc_alive(){
        let mut rng = rand::thread_rng();

        let data_initial = ScAliveCommitmentData{
            fwt_mr: FieldElement::rand(&mut rng),
            bwtr_mr: FieldElement::rand(&mut rng),
            cert_mr: FieldElement::rand(&mut rng),
            scc: FieldElement::rand(&mut rng)
        };
        test_canonical_serialize_deserialize(true, &data_initial);
    }

    #[test]
    fn test_sc_ceased(){
        let mut rng = rand::thread_rng();

        let data_initial = ScCeasedCommitmentData{
            csw_mr: FieldElement::rand(&mut rng)
        };
        test_canonical_serialize_deserialize(true, &data_initial);

    }

    #[test]
    fn test_sc_commitment(){
        let mut rng = rand::thread_rng();

        let data_initial_alive = ScCommitmentData::create_alive(
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng)
        );
        test_canonical_serialize_deserialize(true, &data_initial_alive);

        let data_initial_ceased = ScCommitmentData::create_ceased(
            FieldElement::rand(&mut rng)
        );
        test_canonical_serialize_deserialize(true, &data_initial_ceased);
    }

    #[test]
    fn test_sc_neighbour(){
        let mut rng = rand::thread_rng();

        let id = FieldElement::rand(&mut rng);
        let mpath = new_mt(CMT_MT_HEIGHT).unwrap().finalize().unwrap().get_merkle_path(0).unwrap();
        let sc_data = ScCommitmentData::create_alive(
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng)
        );

        let scn_initial = ScNeighbour::create(id, mpath, sc_data);
        test_canonical_serialize_deserialize(true, &scn_initial);
    }
}