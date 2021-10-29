#[cfg(test)]
mod test {
    use crate::{read_from_file, serialize_to_buffer, deserialize_from_buffer, deserialize_from_buffer_strict, DarlinProof, DarlinVerifierKey};
    use algebra::SerializationError;
    use std::{
        io::{Error as IoError, ErrorKind},
    };

    #[test]
    fn test_strict_deserialization() {
        let proof_path ="./test/strict_deser/sample_final_darlin_proof";
        let vk_path = "./test/strict_deser/sample_final_darlin_vk";

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
