use algebra::{serialize::*, SemanticallyValid};
use crate::{
    type_mapping::{
        Error, CoboundaryMarlinProof, DarlinProof, CoboundaryMarlinVerifierKey,
        DarlinVerifierKey, CoboundaryMarlinProverKey, DarlinProverKey
    },
    proving_system::{
        init::{load_g1_committer_key, load_g2_committer_key},
        error::ProvingSystemError
    }
};

pub mod init;
pub mod verifier;
pub mod error;

#[derive(Copy, Clone, Debug, Eq, PartialEq,)]
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