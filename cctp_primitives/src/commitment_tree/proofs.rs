use crate::commitment_tree::sidechain_tree_alive::SidechainTreeAlive;
use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;
use crate::commitment_tree::{FieldElement, MerklePath};
use crate::commitment_tree::utils::{mpath_to_bytes, mpath_from_bytes, fe_to_bytes, fe_from_bytes, write_value, read_value, write_empty_value, Error};
use std::io::Cursor;

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
struct ScAliveCommitmentData {
    fwt_mr: FieldElement,
    bwtr_mr: FieldElement,
    cert_mr: FieldElement,
    scc: FieldElement
}

impl ScAliveCommitmentData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        write_value(&mut bytes, &fe_to_bytes(&self.fwt_mr));
        write_value(&mut bytes, &fe_to_bytes(&self.bwtr_mr));
        write_value(&mut bytes, &fe_to_bytes(&self.cert_mr));
        write_value(&mut bytes, &fe_to_bytes(&self.scc));
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>{
        let mut stream = Cursor::new(bytes);
        Ok(
            Self{
                fwt_mr:  fe_from_bytes(read_value(&mut stream)?.as_slice())?,
                bwtr_mr: fe_from_bytes(read_value(&mut stream)?.as_slice())?,
                cert_mr: fe_from_bytes(read_value(&mut stream)?.as_slice())?,
                scc:     fe_from_bytes(read_value(&mut stream)?.as_slice())?
            }
        )
    }
}
//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
struct ScCeasedCommitmentData {
    csw_mr: FieldElement
}

impl ScCeasedCommitmentData {
    fn to_bytes(&self) -> Vec<u8> {
        // Not using LV-encoding here due to here is just a single FieldElement value
        fe_to_bytes(&self.csw_mr)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>{
        Ok(
            Self{
                csw_mr: fe_from_bytes(bytes)?
            }
        )
    }
}
//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
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
            Some(SidechainTreeAlive::build_commitment(*sc_id, data.fwt_mr, data.bwtr_mr, data.cert_mr, data.scc))
        } else if let Some(data) = self.sc_ceased.as_ref(){
            Some(SidechainTreeCeased::build_commitment(*sc_id, data.csw_mr))
        } else {
            None // there is no data for commitment building
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        if let Some(sc_alive) = self.sc_alive.as_ref(){
            write_value(&mut bytes, &sc_alive.to_bytes());
        } else {
            write_empty_value(&mut bytes);
        }
        if let Some(sc_ceased) = self.sc_ceased.as_ref(){
            write_value(&mut bytes, &sc_ceased.to_bytes());
        } else {
            write_empty_value(&mut bytes);
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>{
        let mut stream = Cursor::new(bytes);
        Ok(
            Self{
                sc_alive: if let Ok(sc_alive_bytes) = read_value(&mut stream){
                    Some(ScAliveCommitmentData::from_bytes(&sc_alive_bytes)?)
                } else {
                    None
                },
                sc_ceased: if let Ok(sc_ceased_bytes) = read_value(&mut stream){
                    Some(ScCeasedCommitmentData::from_bytes(&sc_ceased_bytes)?)
                } else {
                    None
                }
            }
        )
    }
}
//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
pub struct ScNeighbour{
    pub(crate) id:      FieldElement,    // ID of SC
    pub(crate) mpath:   MerklePath,      // Merkle Path for SC-commitment of an SC with the given ID
    pub(crate) sc_data: ScCommitmentData // data needed to build SC-commitment for the given ID
}

impl ScNeighbour {
    pub(crate) fn create(id:      FieldElement,
                         mpath:   MerklePath,
                         sc_data: ScCommitmentData) -> Self { Self{id, mpath, sc_data} }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        write_value(&mut bytes, &fe_to_bytes(&self.id));
        write_value(&mut bytes, &mpath_to_bytes(&self.mpath));
        write_value(&mut bytes, &self.sc_data.to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>{
        let mut stream = Cursor::new(bytes);
        Ok(
            Self{
                id: fe_from_bytes(read_value(&mut stream)?.as_slice())?,
                mpath: mpath_from_bytes(read_value(&mut stream)?.as_slice())?,
                sc_data: ScCommitmentData::from_bytes(read_value(&mut stream)?.as_slice())?
            }
        )
    }

}
//--------------------------------------------------------------------------------------------------
// Proof of absence of some Sidechain-ID inside of a CommitmentTree
// Contains 0 or 1 or 2 neighbours of an absent ID
#[derive(PartialEq, Debug)]
pub struct ScAbsenceProof{
    pub(crate) left:  Option<ScNeighbour>, // neighbour with a smaller ID
    pub(crate) right: Option<ScNeighbour>  // neighbour with a bigger ID
}

impl ScAbsenceProof {
    pub(crate) fn create(left:  Option<ScNeighbour>, right: Option<ScNeighbour>) -> Self {
        Self{left, right}
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        if let Some(left) = self.left.as_ref(){
            write_value(&mut bytes, &left.to_bytes());
        } else {
            write_empty_value(&mut bytes);
        }
        if let Some(right) = self.right.as_ref(){
            write_value(&mut bytes, &right.to_bytes());
        } else {
            write_empty_value(&mut bytes);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error>{
        let mut stream = Cursor::new(bytes);
        Ok(
            Self{
                left: if let Ok(left_bytes) = read_value(&mut stream){
                    Some(ScNeighbour::from_bytes(&left_bytes)?)
                } else {
                    None
                },
                right: if let Ok(right_bytes) = read_value(&mut stream){
                    Some(ScNeighbour::from_bytes(&right_bytes)?)
                } else {
                    None
                }
            }
        )
    }
}
//--------------------------------------------------------------------------------------------------
// Proof of existence of some SidechainTreeAlive/SidechainTreeCeased inside of a CommitmentTree;
// Actually this is a Merkle Path of SidechainTreeAlive/SidechainTreeCeased inside of a CommitmentTree
#[derive(PartialEq, Debug)]
pub struct ScExistenceProof{
    pub(crate) mpath: MerklePath
}

impl ScExistenceProof {
    pub(crate) fn create(mpath: MerklePath) -> Self {
        Self{mpath}
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Not using LV-encoding here due to here is just a single MerklePath value
        mpath_to_bytes(&self.mpath)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if let Ok(mpath) = mpath_from_bytes(bytes){
            Ok(Self::create(mpath))
        } else {
            Err("Couldn't parse the input bytes".into())
        }
    }
}
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use crate::commitment_tree::proofs::{ScAliveCommitmentData, ScCeasedCommitmentData, ScCommitmentData, ScNeighbour};
    use crate::commitment_tree::{FieldElement, CMT_MT_HEIGHT};
    use algebra::UniformRand;
    use crate::commitment_tree::utils::new_mt;
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
        let data_result = ScAliveCommitmentData::from_bytes(&data_initial.to_bytes());

        assert!(data_result.is_ok());
        assert_eq!(&data_initial, data_result.as_ref().unwrap());
    }

    #[test]
    fn test_sc_ceased(){
        let mut rng = rand::thread_rng();

        let data_initial = ScCeasedCommitmentData{
            csw_mr: FieldElement::rand(&mut rng)
        };
        let data_result = ScCeasedCommitmentData::from_bytes(&data_initial.to_bytes());

        assert!(data_result.is_ok());
        assert_eq!(&data_initial, data_result.as_ref().unwrap());
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
        let data_result_alive = ScCommitmentData::from_bytes(&data_initial_alive.to_bytes());

        assert!(data_result_alive.is_ok());
        assert_eq!(&data_initial_alive, data_result_alive.as_ref().unwrap());

        let data_initial_ceased = ScCommitmentData::create_ceased(
            FieldElement::rand(&mut rng)
        );
        let data_result_ceased = ScCommitmentData::from_bytes(&data_initial_ceased.to_bytes());

        assert!(data_result_ceased.is_ok());
        assert_eq!(&data_initial_ceased, data_result_ceased.as_ref().unwrap());
    }

    #[test]
    fn test_sc_neighbour(){
        let mut rng = rand::thread_rng();

        let id = FieldElement::rand(&mut rng);
        let mpath = new_mt(CMT_MT_HEIGHT).unwrap().finalize().get_merkle_path(0).unwrap();
        let sc_data = ScCommitmentData::create_alive(
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng)
        );

        let scn_initial = ScNeighbour::create(id, mpath, sc_data);
        let scn_result = ScNeighbour::from_bytes(&scn_initial.to_bytes());

        assert!(scn_result.is_ok());
        assert_eq!(&scn_initial, scn_result.as_ref().unwrap());
    }
}
