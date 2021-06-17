use algebra::{serialize::*, SemanticallyValid};
use crate::{
    type_mapping::{
        Error, CoboundaryMarlinProof, DarlinProof, CoboundaryMarlinVerifierKey,
        DarlinVerifierKey, CoboundaryMarlinProverKey, DarlinProverKey, FieldElement,
    },
    proving_system::{
        init::{load_g1_committer_key, load_g2_committer_key},
        error::ProvingSystemError
    }
};

pub mod init;
pub mod verifier;
pub mod error;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub enum ProvingSystem {
    Undefined,
    Darlin,
    CoboundaryMarlin,
}

impl CanonicalSerialize for ProvingSystem {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        match self {
            ProvingSystem::Undefined => CanonicalSerialize::serialize(&0u8, writer),
            ProvingSystem::Darlin => CanonicalSerialize::serialize(&1u8, writer),
            ProvingSystem::CoboundaryMarlin => CanonicalSerialize::serialize(&2u8, writer)
        }
    }

    fn serialized_size(&self) -> usize {
        1
    }
}

impl CanonicalDeserialize for ProvingSystem {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize(reader)?;
        match ps_type_byte {
            0u8 => Ok(ProvingSystem::Undefined),
            1u8 => Ok(ProvingSystem::Darlin),
            2u8 => Ok(ProvingSystem::CoboundaryMarlin),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

// Dummy implementation
impl SemanticallyValid for ProvingSystem {
    fn is_valid(&self) -> bool { true }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZendooProof {
    CoboundaryMarlin(CoboundaryMarlinProof),
    Darlin(DarlinProof),
}

impl ZendooProof {
    pub fn get_proving_system_type(&self) -> ProvingSystem {
        match self {
            ZendooProof::Darlin(_) => ProvingSystem::Darlin,
            ZendooProof::CoboundaryMarlin(_) => ProvingSystem::CoboundaryMarlin,
        }
    }
}

impl CanonicalSerialize for ZendooProof {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProof::Darlin(proof) => {
                CanonicalSerialize::serialize(&1u8, &mut writer)?;
                CanonicalSerialize::serialize(&proof, writer)
            },
            ZendooProof::CoboundaryMarlin(proof) => {
                CanonicalSerialize::serialize(&2u8, &mut writer)?;
                CanonicalSerialize::serialize(&proof, writer)
            },
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            ZendooProof::Darlin(proof) => proof.serialized_size(),
            ZendooProof::CoboundaryMarlin(proof) => proof.serialized_size()
        }
    }

    fn serialize_without_metadata<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProof::Darlin(proof) => {
                CanonicalSerialize::serialize_without_metadata(&proof, writer)
            },
            ZendooProof::CoboundaryMarlin(proof) => {
                CanonicalSerialize::serialize_without_metadata(&proof, writer)
            },
        }
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProof::Darlin(proof) => {
                CanonicalSerialize::serialize_uncompressed(&1u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&proof, writer)
            },
            ZendooProof::CoboundaryMarlin(proof) => {
                CanonicalSerialize::serialize_uncompressed(&2u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&proof, writer)
            },
        }
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        1 + match self {
            ZendooProof::Darlin(proof) => proof.uncompressed_size(),
            ZendooProof::CoboundaryMarlin(proof) => proof.uncompressed_size()
        }
    }
}

impl CanonicalDeserialize for ZendooProof {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProof::Darlin(<DarlinProof as CanonicalDeserialize>::deserialize(reader)?)),
            2u8 => Ok(ZendooProof::CoboundaryMarlin(<CoboundaryMarlinProof as CanonicalDeserialize>::deserialize(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_unchecked(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProof::Darlin(<DarlinProof as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            2u8 => Ok(ZendooProof::CoboundaryMarlin(<CoboundaryMarlinProof as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_uncompressed(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProof::Darlin(<DarlinProof as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            2u8 => Ok(ZendooProof::CoboundaryMarlin(<CoboundaryMarlinProof as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProof::Darlin(<DarlinProof as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            2u8 => Ok(ZendooProof::CoboundaryMarlin(<CoboundaryMarlinProof as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl SemanticallyValid for ZendooProof {
    fn is_valid(&self) -> bool {
        match self {
            ZendooProof::Darlin(proof) => proof.is_valid(),
            ZendooProof::CoboundaryMarlin(proof) => proof.is_valid()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZendooVerifierKey {
    CoboundaryMarlin(CoboundaryMarlinVerifierKey),
    Darlin(DarlinVerifierKey),
}

impl ZendooVerifierKey {
    pub fn get_proving_system_type(&self) -> ProvingSystem {
        match self {
            ZendooVerifierKey::Darlin(_) => ProvingSystem::Darlin,
            ZendooVerifierKey::CoboundaryMarlin(_) => ProvingSystem::CoboundaryMarlin,
        }
    }
}

impl CanonicalSerialize for ZendooVerifierKey {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooVerifierKey::Darlin(vk) => {
                CanonicalSerialize::serialize(&1u8, &mut writer)?;
                CanonicalSerialize::serialize(&vk, writer)
            },
            ZendooVerifierKey::CoboundaryMarlin(vk) => {
                CanonicalSerialize::serialize(&2u8, &mut writer)?;
                CanonicalSerialize::serialize(&vk, writer)
            },
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            ZendooVerifierKey::Darlin(vk) => vk.serialized_size(),
            ZendooVerifierKey::CoboundaryMarlin(vk) => vk.serialized_size()
        }
    }

    fn serialize_without_metadata<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooVerifierKey::Darlin(vk) => {
                CanonicalSerialize::serialize_without_metadata(&vk, writer)
            },
            ZendooVerifierKey::CoboundaryMarlin(vk) => {
                CanonicalSerialize::serialize_without_metadata(&vk, writer)
            },
        }
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooVerifierKey::Darlin(vk) => {
                CanonicalSerialize::serialize_uncompressed(&1u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&vk, writer)
            },
            ZendooVerifierKey::CoboundaryMarlin(vk) => {
                CanonicalSerialize::serialize_uncompressed(&2u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&vk, writer)
            },
        }
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        1 + match self {
            ZendooVerifierKey::Darlin(vk) => vk.uncompressed_size(),
            ZendooVerifierKey::CoboundaryMarlin(vk) => vk.uncompressed_size()
        }
    }
}

impl CanonicalDeserialize for ZendooVerifierKey {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooVerifierKey::Darlin(<DarlinVerifierKey as CanonicalDeserialize>::deserialize(reader)?)),
            2u8 => Ok(ZendooVerifierKey::CoboundaryMarlin(<CoboundaryMarlinVerifierKey as CanonicalDeserialize>::deserialize(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_unchecked(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooVerifierKey::Darlin(<DarlinVerifierKey as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            2u8 => Ok(ZendooVerifierKey::CoboundaryMarlin(<CoboundaryMarlinVerifierKey as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_uncompressed(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooVerifierKey::Darlin(<DarlinVerifierKey as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            2u8 => Ok(ZendooVerifierKey::CoboundaryMarlin(<CoboundaryMarlinVerifierKey as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooVerifierKey::Darlin(<DarlinVerifierKey as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            2u8 => Ok(ZendooVerifierKey::CoboundaryMarlin(<CoboundaryMarlinVerifierKey as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl SemanticallyValid for ZendooVerifierKey {
    fn is_valid(&self) -> bool {
        match self {
            ZendooVerifierKey::Darlin(vk) => vk.is_valid(),
            ZendooVerifierKey::CoboundaryMarlin(vk) => vk.is_valid()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZendooProverKey {
    CoboundaryMarlin(CoboundaryMarlinProverKey),
    Darlin(DarlinProverKey)
}

impl ZendooProverKey {
    pub fn get_proving_system_type(&self) -> ProvingSystem {
        match self {
            ZendooProverKey::Darlin(_) => ProvingSystem::Darlin,
            ZendooProverKey::CoboundaryMarlin(_) => ProvingSystem::CoboundaryMarlin,
        }
    }
}

impl CanonicalSerialize for ZendooProverKey {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProverKey::Darlin(pk) => {
                CanonicalSerialize::serialize(&1u8, &mut writer)?;
                CanonicalSerialize::serialize(&pk, writer)
            },
            ZendooProverKey::CoboundaryMarlin(pk) => {
                CanonicalSerialize::serialize(&2u8, &mut writer)?;
                CanonicalSerialize::serialize(&pk, writer)
            },
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            ZendooProverKey::Darlin(pk) => pk.serialized_size(),
            ZendooProverKey::CoboundaryMarlin(pk) => pk.serialized_size()
        }
    }

    fn serialize_without_metadata<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProverKey::Darlin(pk) => {
                CanonicalSerialize::serialize_without_metadata(&pk, writer)
            },
            ZendooProverKey::CoboundaryMarlin(pk) => {
                CanonicalSerialize::serialize_without_metadata(&pk, writer)
            },
        }
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            ZendooProverKey::Darlin(pk) => {
                CanonicalSerialize::serialize_uncompressed(&1u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&pk, writer)
            },
            ZendooProverKey::CoboundaryMarlin(pk) => {
                CanonicalSerialize::serialize_uncompressed(&2u8, &mut writer)?;
                CanonicalSerialize::serialize_uncompressed(&pk, writer)
            },
        }
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        1 + match self {
            ZendooProverKey::Darlin(pk) => pk.uncompressed_size(),
            ZendooProverKey::CoboundaryMarlin(pk) => pk.uncompressed_size()
        }
    }
}

impl CanonicalDeserialize for ZendooProverKey {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProverKey::Darlin(<DarlinProverKey as CanonicalDeserialize>::deserialize(reader)?)),
            2u8 => Ok(ZendooProverKey::CoboundaryMarlin(<CoboundaryMarlinProverKey as CanonicalDeserialize>::deserialize(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_unchecked(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProverKey::Darlin(<DarlinProverKey as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            2u8 => Ok(ZendooProverKey::CoboundaryMarlin(<CoboundaryMarlinProverKey as CanonicalDeserialize>::deserialize_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize_uncompressed(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProverKey::Darlin(<DarlinProverKey as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            2u8 => Ok(ZendooProverKey::CoboundaryMarlin(<CoboundaryMarlinProverKey as CanonicalDeserialize>::deserialize_uncompressed(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }

    #[inline]
    fn deserialize_uncompressed_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let ps_type_byte: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
        match ps_type_byte {
            1u8 => Ok(ZendooProverKey::Darlin(<DarlinProverKey as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            2u8 => Ok(ZendooProverKey::CoboundaryMarlin(<CoboundaryMarlinProverKey as CanonicalDeserialize>::deserialize_uncompressed_unchecked(reader)?)),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl SemanticallyValid for ZendooProverKey {
    fn is_valid(&self) -> bool {
        match self {
            ZendooProverKey::Darlin(pk) => pk.is_valid(),
            ZendooProverKey::CoboundaryMarlin(pk) => pk.is_valid()
        }
    }
}

/// Utility function: initialize and save to specified paths the G1CommitterKey
/// and G2CommitterKey (iff ProvingSystem::Darlin).
pub fn init_dlog_keys(
    proving_system: ProvingSystem,
    max_segment_size: usize,
    supported_segment_size: usize,
) -> Result<(), Error> {

    if matches!(proving_system, ProvingSystem::Undefined) {
        return Err(ProvingSystemError::UndefinedProvingSystem)?
    }

    load_g1_committer_key(max_segment_size - 1, supported_segment_size - 1)?;

    if matches!(proving_system, ProvingSystem::Darlin) {
        load_g2_committer_key(max_segment_size - 1, supported_segment_size - 1)?
    }

    Ok(())
}

/// Utility function: check that proof and vk belong to the same proving system.
pub fn check_matching_proving_system_type(
    proof: &ZendooProof,
    vk:    &ZendooVerifierKey,
) -> bool
{
    let proof_ps_type = proof.get_proving_system_type();
    let vk_ps_type = vk.get_proving_system_type();

    proof_ps_type == vk_ps_type
}

use marlin::ahp::indexer::IndexInfo;

/// Checks that size of proof and vk for a circuit with given segment_size, indexer_info, proof_type and zk,
/// are smaller than, respectively, max_proof_size and max_vk_size.
pub fn check_proof_vk_size(
    segment_size: usize,
    info: IndexInfo<FieldElement>,
    zk: bool,
    proof_type: ProvingSystem,
    max_proof_size: usize,
    max_vk_size: usize,
) -> bool 
{
    let (proof_size, vk_size) = compute_proof_vk_size(segment_size, info, zk, proof_type);
    proof_size <= max_proof_size && vk_size <= max_vk_size
}

/// Compute size of proof and vk.
/// TODO: Currently, zk = false, gives 33 bytes more and vk size is 7 bytes more. Fix it. 
pub(crate) fn compute_proof_vk_size(
    segment_size: usize,
    info: IndexInfo<FieldElement>,
    zk: bool,
    proof_type: ProvingSystem,
) -> (usize, usize) 
{
    // Compute config data
    let zk_bound: usize = if zk { 1 } else { 0 };
    let segment_size = segment_size.next_power_of_two();
    let h = std::cmp::max(info.num_constraints.next_power_of_two(), info.num_variables.next_power_of_two());
    let k = info.num_non_zero.next_power_of_two();

    // Compute num segments
    let w_z_a_b_segs = ((h + 2 * zk_bound) as f64/segment_size as f64).ceil() as usize;
    let t_segs = ((h as f64/segment_size as f64)).ceil() as usize;
    let z_1_segs = ((h + 3 * zk_bound) as f64/segment_size as f64).ceil() as usize;
    let h_1_segs = ((2 * h + 4 * zk_bound - 2) as f64/segment_size as f64).ceil() as usize;
    let z_2_segs = (k as f64/segment_size as f64).ceil() as usize;
    let h_2_segs =  ((3 * k - 3) as f64/segment_size as f64).ceil() as usize;

    let num_segments = 3 * w_z_a_b_segs + t_segs + z_1_segs + h_1_segs + h_2_segs + z_2_segs;

    // Compute sizes
    let num_evaluations = 22; // indexer polys (12) + prover polys (8) + 2 (z_1 and z_2 are queried at 2 different points) 

    let pc_proof_size = 1 // l_vec_len
        + 2 * algebra::log2_floor(segment_size) * 33 // l_vec and r_vec elems
        + 33 // G_final
        + 32 // c_final
        + 1 // Hiding comm is Some or None
        + if zk { 33 } else { 0 } // If zk we will have the hiding comm
        + 1 // Rand is Some or None
        + if zk { 32 } else { 0 }; // If zk we will have the rand

    let batch_poly_segs = ((3 * k - 4) as f64/segment_size as f64).ceil() as usize;
    let pc_batch_proof_size = (num_evaluations - 2) * 32 // 32 bytes to serialize 1 field element
        + 1 // 1 byte to encode length of evaluations vec
        + 33 * batch_poly_segs // num segs of the highest degree polynomial as the batch poly will have this degree too
        + 1 // 1 byte to encode length of segments vec
        + pc_proof_size as usize;

    let proof_size = num_segments * 33 // 33 bytes used for point compressed representation
        + 8 // 1 byte for each poly to encode shifted comm being Some or None
        + 8 // 1 byte for each poly to encode length of segments vector
        + num_evaluations * 32
        + pc_batch_proof_size
        + match proof_type {
            ProvingSystem::Darlin => 
                2 * // 2 deferred accumulators
                (
                    33 // G_final
                    + 1 // xi_s len
                    + algebra::log2_floor(segment_size) * 16 // xi_s (only 128 bits long)
                ),
            ProvingSystem::CoboundaryMarlin => 0,
            _ => unreachable!()
        } as usize;

    let indexer_polys_num_segs = (k as f64/segment_size as f64).ceil() as usize;
    let vk_size = 24 // index_info
        + 1 // indexer comms vec len
        + indexer_polys_num_segs * 33 * 12 // segment commitments for each indexer poly
        + 12 // comms vec len for each indexer poly
        + 12 // shifted comm some or none for each indexer poly
    ;
    
    (proof_size, vk_size)
}

#[allow(dead_code)]
/// Given segment_size, density, zk, proof_type, return the log2 of the maximum value of |H|
/// s.t. proof size is <= max_proof_size and vk size is <= max_vk_size, and the
/// corresponding values of proof size and vk size
pub(crate) fn compute_max_domain_h_size(
    segment_size: usize,
    density: usize,
    zk: bool,
    max_proof_size: usize,
    max_vk_size: usize,
    proof_type: ProvingSystem
) -> (usize, usize, usize)
{
    let segment_size = segment_size.next_power_of_two();
    let mut max_supported_h_size = 0;
    let mut max_supported_proof_size = 0;
    let mut max_supported_vk_size = 0;

    loop {
        let h = 1 << max_supported_h_size;
        let k = (h * density).next_power_of_two(); // |K|/|H| = density
        let mut info = IndexInfo::<FieldElement>::default();
        info.num_constraints = h;
        info.num_variables = h;
        info.num_non_zero = k;
        
        let (proof_size, vk_size) = compute_proof_vk_size(segment_size, info, zk, proof_type); 

        if proof_size > max_proof_size || vk_size > max_vk_size {
            break (max_supported_h_size - 1, max_supported_proof_size, max_supported_vk_size)
        }

        max_supported_proof_size = proof_size;
        max_supported_vk_size = vk_size;
        max_supported_h_size += 1;
    }
}

#[test]
fn test_check_proof_vk_size() {
    let max_proof_size = 7000;
    let max_vk_size = 4000;
    
    for density in 2..5 {
        for proof_type in vec![ProvingSystem::CoboundaryMarlin, ProvingSystem::Darlin].into_iter() {
            for zk in vec![true, false].into_iter() {
                for size in 15..19 {
                    let segment_size = 1 << size;
                    let (h, proof_size, vk_size) = compute_max_domain_h_size(segment_size, density, zk, max_proof_size, max_vk_size, proof_type);
                    println!(
                        "For Density: {}, MaxProofSize: {}, MaxVkSize: {}, ProofType: {:?}, Zk: {}, SegmentSize: 1 << {}, Max supported H size is: 1 << {}, Proof size: {} bytes, Vk size: {} bytes",
                        density, max_proof_size, max_vk_size, proof_type, zk, size, h, proof_size, vk_size
                    );

                    let mut info = IndexInfo::<FieldElement>::default();
                    let h = 1 << h;
                    info.num_constraints = h;
                    info.num_variables = h;
                    info.num_non_zero = (h * density).next_power_of_two();
                    assert!(check_proof_vk_size(segment_size, info, zk, proof_type, max_proof_size, max_vk_size));

                    let h = h * 2;
                    info.num_constraints = h;
                    info.num_variables = h;
                    info.num_non_zero = (h * density).next_power_of_two();
                    assert!(!check_proof_vk_size(segment_size, info, zk, proof_type, max_proof_size, max_vk_size))
                }
            }
        }
    }
}