//! # Merkle Tree
//!
//! `merkle_tree` exposes functions to compute a bit vector Merkle tree.

use super::compression;
use crate::type_mapping::*;

use algebra::{ToConstraintField, log2};
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTree;

use bit_vec::BitVec;


/// Computes the root hash of the Merkle tree created as a representation
/// of `uncompressed_bit_vector`.
///
/// The input byte array is expected to have a Big Endian bit order, for example:
/// Bit Array [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0] <=> Byte Array [1, 2]
/// 
/// # Examples
///
/// ```
/// use cctp_primitives::bit_vector::merkle_tree::*;
///
/// let bit_vector: Vec<u8> = (0..64).collect();
/// let merkle_root = merkle_root_from_bytes(&bit_vector).unwrap();
/// 
/// ```
pub fn merkle_root_from_bytes(uncompressed_bit_vector: &[u8]) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let bv = BitVec::from_bytes(&uncompressed_bit_vector);
    let bool_vector: Vec<bool> = bv.into_iter().map(|x| x).collect();

    // The bit vector may contain some padding bits at the end that have to be discarded
    let real_bit_vector_size: usize = bool_vector.len() - bool_vector.len() % FIELD_CAPACITY;

    let merkle_tree_height = log2(real_bit_vector_size / FIELD_CAPACITY) as usize;
    let num_leaves = 1 << merkle_tree_height;
    let mut mt = GingerMHT::init(
        merkle_tree_height,
        num_leaves,
    )?;

    let leaves = bool_vector[..real_bit_vector_size].to_field_elements()?;

    assert_eq!(leaves.len(), num_leaves);

    for leaf in leaves.into_iter() {
        mt.append(leaf)?;
    }

    match mt.finalize_in_place().root() {
        Some(x) => Ok(x),
        None => Err("Unable to compute the merkle tree root hash")?
    }

}

/// Computes the root hash of the Merkle tree created as a representation
/// of `compressed_bit_vector`.
/// The function internally decompresses the bit_vector by using the algorithm
/// specified by the first byte of the vector itself and requires the
/// decompressed bit vector to have exactly `expected_uncompressed_size` bytes.
///
/// The input byte array is expected to have a Big Endian bit order, for example:
/// Bit Array [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0] <=> Byte Array [1, 2]
/// 
/// # Examples
///
/// ```
/// use cctp_primitives::bit_vector::compression::*;
/// use cctp_primitives::bit_vector::merkle_tree::*;
///
/// let bit_vector: Vec<u8> = (0..64).collect();
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
/// let merkle_root = merkle_root_from_compressed_bytes(&compressed_bit_vector, bit_vector.len()).unwrap();
/// 
/// ```
pub fn merkle_root_from_compressed_bytes(compressed_bit_vector: &[u8], expected_uncompressed_size: usize) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let uncompressed_bit_vector = compression::decompress_bit_vector(compressed_bit_vector, expected_uncompressed_size)?;
    merkle_root_from_bytes(&uncompressed_bit_vector)

}

pub fn merkle_root_from_compressed_bytes_without_checks(compressed_bit_vector: &[u8]) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let uncompressed_bit_vector = compression::decompress_bit_vector_without_checks(compressed_bit_vector)?;
    merkle_root_from_bytes(&uncompressed_bit_vector)

}

#[cfg(test)]
mod test {

    use super::*;
    use compression::{CompressionAlgorithm, compress_bit_vector};

    use std::fmt::Write;

    #[test]
    fn expected_size() {
        let mut bit_vector: Vec<u8> = vec![0; 63];

        // Expect for an error because of the different uncompressed size.
        assert!(merkle_root_from_compressed_bytes(&bit_vector, bit_vector.len()).is_err());
        // No errors expected if the uncompressed size is fine.
        assert!(merkle_root_from_compressed_bytes(&bit_vector, bit_vector.len() - 1).is_ok());

        bit_vector.clear();
        bit_vector.push(0);

        for i in 0..63 {
            bit_vector.push(i);
        }
        
        assert!(merkle_root_from_compressed_bytes(&bit_vector, bit_vector.len() - 1).is_ok());

    }

    #[test]
    fn without_size_checks() {
        let mut bit_vector: Vec<u8> = vec![0; 63];
        assert!(merkle_root_from_compressed_bytes_without_checks(&bit_vector).is_ok());

        bit_vector.clear();
        bit_vector.push(0);

        for i in 0..63 {
            bit_vector.push(i);
        }

        assert!(merkle_root_from_compressed_bytes_without_checks(&bit_vector).is_ok());
    }

    #[test]
    fn check_root_hash_computation() {

        let test_data_set = vec![
            ("./test/merkle_tree/bvt_4x254_bytes.dat", "./test/merkle_tree/bvt_4x254_root.txt"),
            ("./test/merkle_tree/bvt_8x254_bytes.dat", "./test/merkle_tree/bvt_8x254_root.txt"),
            ("./test/merkle_tree/bvt_16x254_bytes.dat", "./test/merkle_tree/bvt_16x254_root.txt"),
            ("./test/merkle_tree/bvt_32x254_bytes.dat", "./test/merkle_tree/bvt_32x254_root.txt"),
            ("./test/merkle_tree/bvt_64x254_bytes.dat", "./test/merkle_tree/bvt_64x254_root.txt"),
        ];

        for test_data in test_data_set {
            check_root_hash_computation_from_file(test_data.0, test_data.1);
        }
    }
 
    fn check_root_hash_computation_from_file(bit_vector_path: &str, root_hash_path: &str) {
        let mut raw_byte_vector: Vec<u8> = std::fs::read(bit_vector_path).unwrap();
        let root_hash = std::fs::read_to_string(root_hash_path).unwrap();

        let computed_root = merkle_root_from_bytes(&raw_byte_vector).unwrap();
        let compressed_bit_vector = compress_bit_vector(&raw_byte_vector, CompressionAlgorithm::Uncompressed).unwrap();
        let compressed_root = merkle_root_from_compressed_bytes(&compressed_bit_vector, raw_byte_vector.len()).unwrap();
        let computed_root_hash = field_element_to_hex_string(computed_root);
        let compressed_root_hash = field_element_to_hex_string(compressed_root);

        assert_eq!(compressed_root_hash, computed_root_hash);
        assert_eq!(root_hash, computed_root_hash);

        println!("Expected root hash: {}", root_hash);
        println!("Computed root hash: {}", computed_root_hash);
        println!("Compressed root hash: {}", compressed_root_hash);

        // Add some bytes to make the merkle root hash change.
        raw_byte_vector.extend(vec![1;  raw_byte_vector.len()]);
        let updated_root = merkle_root_from_bytes(&raw_byte_vector).unwrap();
        let updated_root_hash = field_element_to_hex_string(updated_root);

        // Check that the root hash is different than the previous one.
        assert!(root_hash != updated_root_hash);
    }

    fn field_element_to_hex_string(field_element: FieldElement) -> String {
        use algebra::{ToBytes, to_bytes};

        let mut hex_string = String::from("0x");
        let field_element_bytes = to_bytes!(field_element).unwrap();

        for byte in field_element_bytes {
            write!(hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }
}