use crate::commitment_tree::sidechain_tree_alive::SidechainTreeAlive;
use crate::commitment_tree::sidechain_tree_ceased::SidechainTreeCeased;
use crate::commitment_tree::{FieldElement, MerklePath};
use std::io::{Read, Write, Result as IoResult};
use algebra::{ToBytes, FromBytes};

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
struct ScAliveCommitmentData {
    fwt_mr: FieldElement,
    bwtr_mr: FieldElement,
    cert_mr: FieldElement,
    scc: FieldElement
}

impl ToBytes for ScAliveCommitmentData {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()>
    {
        self.fwt_mr.write(&mut writer)?;
        self.bwtr_mr.write(&mut writer)?;
        self.cert_mr.write(&mut writer)?;
        self.scc.write(writer)
    }
}

impl FromBytes for ScAliveCommitmentData {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let fwt_mr = FieldElement::read(&mut reader)?;
        let bwtr_mr = FieldElement::read(&mut reader)?;
        let cert_mr = FieldElement::read(&mut reader)?;
        let scc = FieldElement::read(reader)?;

        Ok(Self {
            fwt_mr,
            bwtr_mr,
            cert_mr,
            scc
        })
    }
}

//--------------------------------------------------------------------------------------------------
#[derive(PartialEq, Debug)]
struct ScCeasedCommitmentData {
    csw_mr: FieldElement
}

impl ToBytes for ScCeasedCommitmentData {
    fn write<W: Write>(&self, writer: W) -> IoResult<()>
    {
        self.csw_mr.write(writer)
    }
}

impl FromBytes for ScCeasedCommitmentData {
    fn read<R: Read>(reader: R) -> IoResult<Self> {
        let csw_mr = FieldElement::read(reader)?;

        Ok(Self { csw_mr })
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
}

impl ToBytes for ScCommitmentData {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()>
    {
        self.sc_alive.write(&mut writer)?;
        self.sc_ceased.write(&mut writer)
    }
}

impl FromBytes for ScCommitmentData {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let sc_alive = Option::<ScAliveCommitmentData>::read(&mut reader)?;
        let sc_ceased = Option::<ScCeasedCommitmentData>::read(reader)?;

        Ok(Self { sc_alive, sc_ceased })
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

}

impl ToBytes for ScNeighbour {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()>
    {
        self.id.write(&mut writer)?;
        self.mpath.write(&mut writer)?;
        self.sc_data.write(writer)
    }
}

impl FromBytes for ScNeighbour {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let id = FieldElement::read(&mut reader)?;
        let mpath = MerklePath::read(&mut reader)?;
        let sc_data = ScCommitmentData::read(&mut reader)?;

        Ok(Self { id, mpath, sc_data })
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
}

impl ToBytes for ScAbsenceProof {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()>
    {
        self.left.write(&mut writer)?;
        self.right.write(&mut writer)
    }
}

impl FromBytes for ScAbsenceProof {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let left = Option::<ScNeighbour>::read(&mut reader)?;
        let right = Option::<ScNeighbour>::read(reader)?;

        Ok(Self { left, right })
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
        Self{ mpath }
    }
}

impl ToBytes for ScExistenceProof {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()>
    {
        self.mpath.write(&mut writer)
    }
}

impl FromBytes for ScExistenceProof {
    fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let mpath = MerklePath::read(&mut reader)?;

        Ok(Self { mpath })
    }
}

//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use crate::commitment_tree::proofs::{ScAliveCommitmentData, ScCeasedCommitmentData, ScCommitmentData, ScNeighbour};
    use crate::commitment_tree::{FieldElement, CMT_MT_HEIGHT};
    use algebra::{ToBytes, to_bytes, FromBytes, UniformRand};
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
        let data_result = ScAliveCommitmentData::read(to_bytes!(data_initial).unwrap().as_slice());

        assert!(data_result.is_ok());
        assert_eq!(&data_initial, data_result.as_ref().unwrap());
    }

    #[test]
    fn test_sc_ceased(){
        let mut rng = rand::thread_rng();

        let data_initial = ScCeasedCommitmentData{
            csw_mr: FieldElement::rand(&mut rng)
        };
        let data_result = ScCeasedCommitmentData::read(to_bytes!(data_initial).unwrap().as_slice());

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
        let data_result_alive = ScCommitmentData::read(to_bytes!(data_initial_alive).unwrap().as_slice());

        assert!(data_result_alive.is_ok());
        assert_eq!(&data_initial_alive, data_result_alive.as_ref().unwrap());

        let data_initial_ceased = ScCommitmentData::create_ceased(
            FieldElement::rand(&mut rng)
        );
        let data_result_ceased = ScCommitmentData::read(to_bytes!(data_initial_ceased).unwrap().as_slice());

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
        let scn_result = ScNeighbour::read(to_bytes!(scn_initial).unwrap().as_slice());

        assert!(scn_result.is_ok());
        assert_eq!(&scn_initial, scn_result.as_ref().unwrap());
    }
}
