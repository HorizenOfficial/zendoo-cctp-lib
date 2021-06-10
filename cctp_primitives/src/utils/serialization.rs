use algebra::{serialize::*, SemanticallyValid};
use std::{path::Path, fs::File, io::{BufReader, BufWriter}};

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

pub fn deserialize_from_buffer_debug<T: CanonicalDeserialize + SemanticallyValid>(
    buffer: &[u8],
    semantic_checks:        bool,
    deserialization_checks: bool,
    compressed:             bool,
) ->  Result<T, SerializationError>
{
    let t = match (deserialization_checks, compressed) {
        (true, true) => T::deserialize(buffer),
        (true, false) => T::deserialize_uncompressed(buffer),
        (false, false) => T::deserialize_uncompressed_unchecked(buffer),
        (false, true) => T::deserialize_unchecked(buffer)
    }?;

    if semantic_checks && !t.is_valid() {
        return Err(SerializationError::InvalidData)
    }

    Ok(t)
}

pub fn serialize_to_buffer<T: CanonicalSerialize>(to_write: &T) -> Result<Vec<u8>, SerializationError> {
    let mut buffer = Vec::with_capacity(to_write.serialized_size());
    CanonicalSerialize::serialize(to_write, &mut buffer)?;
    Ok(buffer)
}

pub fn serialize_to_buffer_debug<T: CanonicalSerialize>(
    to_write:               &T,
    compressed:             bool,
) ->  Result<Vec<u8>, SerializationError>
{
    let mut buffer = Vec::with_capacity(to_write.serialized_size());
    if compressed {
        CanonicalSerialize::serialize(to_write, &mut buffer)?;
    } else {
        CanonicalSerialize::serialize_uncompressed(to_write, &mut buffer)?;
    }
    Ok(buffer)
}

pub const DEFAULT_BUF_SIZE: usize = 1 << 20;

pub fn read_from_file<T: CanonicalDeserialize>(file_path: &Path) -> Result<T, SerializationError> {
    let fs = File::open(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    let reader = BufReader::with_capacity(DEFAULT_BUF_SIZE, fs);
    T::deserialize(reader)
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
    let fs = File::create(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    let mut writer = BufWriter::with_capacity(DEFAULT_BUF_SIZE, fs);
    CanonicalSerialize::serialize(to_write, &mut writer)?;
    writer.flush().map_err(|e| SerializationError::IoError(e))?;
    Ok(())
}

pub fn is_valid<T: SemanticallyValid>(to_check: &T) -> bool {
    T::is_valid(to_check)
}