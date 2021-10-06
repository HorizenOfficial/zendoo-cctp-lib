use algebra::{serialize::*, SemanticallyValid};
use std::{path::Path, fs::File, io::{BufReader, BufWriter}};

/// Deserialize from `buffer` a compressed or uncompressed element, depending on the value of
/// `compressed` flag, and perform checks on it, depending on the value of `semantic_checks` flag.
/// `compressed` can be optional, due to some types being uncompressable;
/// `semantic_checks` can be optional, due to some types having no checks to be performed,
/// or trivial checks already performed a priori during serialization.
pub fn deserialize_from_buffer<T: CanonicalDeserialize + SemanticallyValid>(
    buffer: &[u8],
    semantic_checks:        Option<bool>,
    compressed:             Option<bool>,
) ->  Result<T, SerializationError>
{
    let semantic_checks = semantic_checks.unwrap_or(false);
    let compressed = compressed.unwrap_or(false);

    let t = if compressed {
        T::deserialize_unchecked(buffer)
    } else {
        T::deserialize_uncompressed_unchecked(buffer)
    }?;

    if semantic_checks && !t.is_valid() {
        return Err(SerializationError::InvalidData)
    }

    Ok(t)
}

/// Serialize to buffer, choosing whether to use compressed representation or not,
/// depending on the value of `compressed` flag.
/// `compressed` can be optional, due to some types being uncompressable.
pub fn serialize_to_buffer<T: CanonicalSerialize>(
    to_write:               &T,
    compressed:             Option<bool>,
) ->  Result<Vec<u8>, SerializationError>
{
    let compressed = compressed.unwrap_or(false);

    let mut buffer;
    if compressed {
        buffer = Vec::with_capacity(to_write.serialized_size());
        CanonicalSerialize::serialize(to_write, &mut buffer)?;
    } else {
        buffer = Vec::with_capacity(to_write.uncompressed_size());
        CanonicalSerialize::serialize_uncompressed(to_write, &mut buffer)?;
    }
    Ok(buffer)
}

pub const DEFAULT_BUF_SIZE: usize = 1 << 20;


/// Deserialize from the file at `file_path` a compressed or uncompressed element,
/// depending on the value of `compressed` flag, and perform checks on it, depending
/// on the value of `semantic_checks` flag.
/// `compressed` can be optional, due to some types being uncompressable;
/// `semantic_checks` can be optional, due to some types having no checks to be performed,
/// or trivial checks already performed a priori during serialization.
pub fn read_from_file<T: CanonicalDeserialize + SemanticallyValid>(
    file_path: &Path,
    semantic_checks:        Option<bool>,
    compressed:             Option<bool>,
) ->  Result<T, SerializationError>
{
    let semantic_checks = semantic_checks.unwrap_or(false);
    let compressed = compressed.unwrap_or(false);

    let fs = File::open(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    let reader = BufReader::with_capacity(DEFAULT_BUF_SIZE, fs);

    let t = if compressed {
        T::deserialize_unchecked(reader)
    } else {
        T::deserialize_uncompressed_unchecked(reader)
    }?;

    if semantic_checks && !t.is_valid() {
        return Err(SerializationError::InvalidData)
    }

    Ok(t)
}

/// Serialize to file, choosing whether to use compressed representation or not,
/// depending on the value of `compressed` flag.
/// `compressed` can be optional, due to some types being uncompressable.
pub fn write_to_file<T: CanonicalSerialize>(
    to_write:               &T,
    file_path:              &Path,
    compressed:             Option<bool>,
) ->  Result<(), SerializationError>
{
    let compressed = compressed.unwrap_or(false);

    let fs = File::create(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    let mut writer = BufWriter::with_capacity(DEFAULT_BUF_SIZE, fs);

    if compressed {
        CanonicalSerialize::serialize(to_write, &mut writer)?;
    } else {
        CanonicalSerialize::serialize_uncompressed(to_write, &mut writer)?;
    }

    writer.flush().map_err(|e| SerializationError::IoError(e))?;
    Ok(())
}

pub fn is_valid<T: SemanticallyValid>(to_check: &T) -> bool {
    T::is_valid(to_check)
}