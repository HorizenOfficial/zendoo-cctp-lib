use crate::MC_PK_SIZE;
use algebra::serialize::*;

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
            max_compressed_byte_size: 0u32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct BackwardTransfer {
    pub pk_dest: [u8; MC_PK_SIZE],
    pub amount: u64,
}

impl Default for BackwardTransfer {
    fn default() -> Self {
        Self {
            pk_dest: [0u8; MC_PK_SIZE],
            amount: 0u64,
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
        Ok(Self { pk_dest, amount })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::serialize_to_buffer;

    #[test]
    fn test_serialized_size() {
        {
            let test_bvec = BitVectorElementsConfig::default();
            assert_eq!(serialize_to_buffer(&test_bvec, None).unwrap().len(), 8);
            assert_eq!(serialize_to_buffer(&test_bvec, None).unwrap().len(), 8);
            test_canonical_serialize_deserialize(true, &test_bvec);
        }

        {
            let test_bt = BackwardTransfer::default();
            assert_eq!(
                serialize_to_buffer(&test_bt, None).unwrap().len(),
                test_bt.serialized_size()
            );
            assert_eq!(
                serialize_to_buffer(&test_bt, None).unwrap().len(),
                test_bt.uncompressed_size()
            );

            test_canonical_serialize_deserialize(true, &test_bt);
        }
    }
}
