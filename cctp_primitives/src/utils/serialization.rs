use algebra::{serialize::*, SemanticallyValid};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Cursor, Error as IoError, ErrorKind, Read},
    path::Path,
};

fn _deserialize_inner<R: Read, T: CanonicalDeserialize + SemanticallyValid>(
    reader: R,
    semantic_checks: Option<bool>,
    compressed: Option<bool>,
) -> Result<T, SerializationError> {
    let semantic_checks = semantic_checks.unwrap_or(false);
    let compressed = compressed.unwrap_or(false);

    let t = if compressed {
        T::deserialize_unchecked(reader)
    } else {
        T::deserialize_uncompressed_unchecked(reader)
    }?;

    if semantic_checks && !t.is_valid() {
        return Err(SerializationError::InvalidData);
    }

    Ok(t)
}

/// Deserialize from `buffer` a compressed or uncompressed element, depending on the value of
/// `compressed` flag, and perform checks on it, depending on the value of `semantic_checks` flag.
/// `compressed` can be optional, due to some types being uncompressable;
/// `semantic_checks` can be optional, due to some types having no checks to be performed,
/// or trivial checks already performed a priori during serialization.
pub fn deserialize_from_buffer<T: CanonicalDeserialize + SemanticallyValid>(
    buffer: &[u8],
    semantic_checks: Option<bool>,
    compressed: Option<bool>,
) -> Result<T, SerializationError> {
    _deserialize_inner(buffer, semantic_checks, compressed)
}

/// Deserialize from `buffer` a compressed or uncompressed element, depending on the value of
/// `compressed` flag, and perform checks on it, depending on the value of `semantic_checks` flag.
/// `compressed` can be optional, due to some types being uncompressable;
/// `semantic_checks` can be optional, due to some types having no checks to be performed,
/// or trivial checks already performed a priori during serialization.
/// If there are still bytes to read in `buffer` after deserializing T, this function returns an error.
pub fn deserialize_from_buffer_strict<T: CanonicalDeserialize + SemanticallyValid>(
    buffer: &[u8],
    semantic_checks: Option<bool>,
    compressed: Option<bool>,
) -> Result<T, SerializationError> {
    // Wrap buffer in a cursor
    let buff_len = buffer.len() as u64;
    let mut buffer = Cursor::new(buffer);

    // Deserialize t
    let t = _deserialize_inner(&mut buffer, semantic_checks, compressed)?;

    let position = buffer.position();
    if position != buff_len {
        return Err(SerializationError::IoError(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "Oversized data. Read {} but buff len is {}",
                position, buff_len
            ),
        )));
    }

    Ok(t)
}

/// Serialize to buffer, choosing whether to use compressed representation or not,
/// depending on the value of `compressed` flag.
/// `compressed` can be optional, due to some types being uncompressable.
pub fn serialize_to_buffer<T: CanonicalSerialize>(
    to_write: &T,
    compressed: Option<bool>,
) -> Result<Vec<u8>, SerializationError> {
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
    semantic_checks: Option<bool>,
    compressed: Option<bool>,
) -> Result<T, SerializationError> {
    let fs = File::open(file_path).map_err(|e| SerializationError::IoError(e))?;
    let reader = BufReader::with_capacity(DEFAULT_BUF_SIZE, fs);

    _deserialize_inner(reader, semantic_checks, compressed)
}

/// Serialize to file, choosing whether to use compressed representation or not,
/// depending on the value of `compressed` flag.
/// `compressed` can be optional, due to some types being uncompressable.
pub fn write_to_file<T: CanonicalSerialize>(
    to_write: &T,
    file_path: &Path,
    compressed: Option<bool>,
) -> Result<(), SerializationError> {
    let compressed = compressed.unwrap_or(false);

    let fs = File::create(file_path).map_err(|e| SerializationError::IoError(e))?;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::type_mapping::{DarlinProof, DarlinVerifierKey};
    use std::{
        io::{Error as IoError, ErrorKind},
        path::Path,
    };

    #[test]
    fn test_strict_deserialization() {
        let proof_path = Path::new("./test/strict_deser/sample_final_darlin_proof");
        let vk_path = Path::new("./test/strict_deser/sample_final_darlin_vk");

        let proof = read_from_file::<DarlinProof>(&proof_path, Some(true), Some(true)).unwrap(); // Must pass
        let vk = read_from_file::<DarlinVerifierKey>(&vk_path, Some(true), Some(true)).unwrap(); // Must pass

        // Serialize proof and vk to a buffer
        let mut proof_bytes = serialize_to_buffer(&proof, Some(true)).unwrap();
        let proof_len = proof_bytes.len();

        let mut vk_bytes = serialize_to_buffer(&vk, Some(true)).unwrap();
        let vk_len = vk_bytes.len();

        // Test strict deserialization (proof) from buffer is fine with data of correct size
        assert!(deserialize_from_buffer::<DarlinProof>(
            proof_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());
        assert!(deserialize_from_buffer_strict::<DarlinProof>(
            proof_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());

        // Test strict deserialization (vk) from buffer is fine with data of correct size
        assert!(deserialize_from_buffer::<DarlinVerifierKey>(
            vk_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());
        assert!(deserialize_from_buffer_strict::<DarlinVerifierKey>(
            vk_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());

        // Let's append a new byte to proof_bytes and vk_bytes and check that deserialization strict fails
        proof_bytes.push(5u8);
        vk_bytes.push(5u8);

        let expected_proof_bytes_error = SerializationError::IoError(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "Oversized data. Read {} but buff len is {}",
                proof_len,
                proof_len + 1
            ),
        ))
        .to_string();

        let expected_vk_bytes_error = SerializationError::IoError(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "Oversized data. Read {} but buff len is {}",
                vk_len,
                vk_len + 1
            ),
        ))
        .to_string();

        assert_eq!(
            deserialize_from_buffer_strict::<DarlinProof>(
                proof_bytes.as_slice(),
                Some(true),
                Some(true)
            )
            .unwrap_err()
            .to_string(),
            expected_proof_bytes_error
        );
        assert_eq!(
            deserialize_from_buffer_strict::<DarlinVerifierKey>(
                vk_bytes.as_slice(),
                Some(true),
                Some(true)
            )
            .unwrap_err()
            .to_string(),
            expected_vk_bytes_error
        );

        // Non-strict deserialization should still pass instead
        assert!(deserialize_from_buffer::<DarlinProof>(
            proof_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());
        assert!(deserialize_from_buffer::<DarlinVerifierKey>(
            vk_bytes.as_slice(),
            Some(true),
            Some(true)
        )
        .is_ok());
    }
}
