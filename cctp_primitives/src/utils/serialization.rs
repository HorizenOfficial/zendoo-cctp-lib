use algebra::{serialize::*, SemanticallyValid};
use std::{
    path::Path, fs::File, io::{Read, Write}
};
use crate::type_mapping::ProvingSystem;


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

// Common functions useful to serialize/deserialize structs
pub fn deserialize_from_buffer<T: CanonicalDeserialize>(buffer: &[u8]) ->  Result<T, SerializationError>
{
    T::deserialize(buffer)
}

pub fn deserialize_from_buffer_checked<T: CanonicalDeserialize + SemanticallyValid>(buffer: &[u8]) ->  Result<T, SerializationError>
{
    let elem = deserialize_from_buffer::<T>(buffer)?;
    if !elem.is_valid() {
        return Err(SerializationError::InvalidData)
    }
    Ok(elem)
}

pub fn serialize_to_buffer<T: CanonicalSerialize>(to_write: &T) -> Result<Vec<u8>, SerializationError> {
    let mut buffer = Vec::with_capacity(to_write.serialized_size());
    CanonicalSerialize::serialize(to_write, &mut buffer)?;
    Ok(buffer)
}

pub fn read_from_file<T: CanonicalDeserialize>(file_path: &Path) -> Result<T, SerializationError> {
    let fs = File::open(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    T::deserialize(fs)
}

pub fn read_from_file_checked<T: CanonicalDeserialize + SemanticallyValid>(file_path: &Path) -> Result<T, SerializationError>
{
    let elem = read_from_file::<T>(file_path)?;
    if !elem.is_valid() {
        return Err(SerializationError::InvalidData)
    }
    Ok(elem)
}

pub fn write_to_file<T: CanonicalSerialize>(to_write: &T, file_path: &Path) -> Result<(), SerializationError>
{
    let mut fs = File::create(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    CanonicalSerialize::serialize(to_write, &mut fs)?;
    Ok(())
}

pub fn is_valid<T: SemanticallyValid>(to_check: &T) -> bool {
    T::is_valid(to_check)
}