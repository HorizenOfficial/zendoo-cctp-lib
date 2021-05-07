use algebra::serialize::*;
use crate::type_mapping::MC_PK_SIZE;

#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[repr(C)]
pub struct BitVectorElementsConfig {
    pub bit_vector_size_bits: u32,
    pub max_compressed_byte_size: u32,
}

impl Default for BitVectorElementsConfig {
    fn default() -> Self {
        Self {
            bit_vector_size_bits: 0u32,
            max_compressed_byte_size: 0u32
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq,)]
#[repr(C)]
pub struct BackwardTransfer {
    pub pk_dest: [u8; MC_PK_SIZE],
    pub amount: u64,
}

impl Default for BackwardTransfer {
    fn default() -> Self {
        Self {
            pk_dest: [0u8; MC_PK_SIZE],
            amount: 0u64
        }
    }
}

impl CanonicalSerialize for BackwardTransfer {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        CanonicalSerialize::serialize_without_metadata(&self.pk_dest[..], &mut writer)?;
        CanonicalSerialize::serialize(&self.amount, writer)
    }

    fn serialized_size(&self) -> usize {
        28
    }
}

impl CanonicalDeserialize for BackwardTransfer {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut pk_dest = [0u8; MC_PK_SIZE];
        for i in 0..MC_PK_SIZE {
            let byte: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            pk_dest[i] = byte;
        }
        let amount: u64 = CanonicalDeserialize::deserialize(reader)?;
        Ok(Self {pk_dest, amount})
    }
}

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::serialization::serialize_to_buffer;

    #[test]
    fn test_serialized_size() {

        {
            let test_bvec = BitVectorElementsConfig::default();
            assert_eq!(serialize_to_buffer(&test_bvec).unwrap().len(), 8);
            test_canonical_serialize_deserialize(true, &test_bvec);
        }

        {
            let test_bt = BackwardTransfer::default();
            assert_eq!(serialize_to_buffer(&test_bt).unwrap().len(), test_bt.serialized_size());
            test_canonical_serialize_deserialize(true, &test_bt);
        }

        {
            let test_ps = ProvingSystem::Undefined;
            assert_eq!(serialize_to_buffer(&test_ps).unwrap().len(), 1);
            test_canonical_serialize_deserialize(true, &test_ps);
        }
    }
}