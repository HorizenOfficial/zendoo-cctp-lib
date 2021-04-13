//! # Merkle Tree
//!
//! `merkle_tree` exposes functions to compute a bit vector Merkle tree.

use super::compression;
use crate::type_mapping::*;

use algebra::ToConstraintField;
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTree;

use bit_vec::BitVec;

type Error = Box<dyn std::error::Error>;

const MERKLE_TREE_HEIGHT: usize = 12;

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
/// let bit_vector: Vec<u8> = (0..100).collect();
/// let merkle_root = merkle_root_from_bytes(&bit_vector).unwrap();
/// 
/// ```
pub fn merkle_root_from_bytes(uncompressed_bit_vector: &[u8]) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let bv = BitVec::from_bytes(&uncompressed_bit_vector);
    let bool_vector: Vec<bool> = bv.into_iter().map(|x| x).collect();

    let num_leaves = 1 << MERKLE_TREE_HEIGHT;
    let mut mt = GingerMHT::init(
        MERKLE_TREE_HEIGHT,
        num_leaves,
    );

    let leaves = bool_vector.to_field_elements()?;

    leaves[..].iter().for_each(|&leaf| { mt.append(leaf); });

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
/// let bit_vector: Vec<u8> = (0..100).collect();
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
/// let merkle_root = merkle_root_from_compressed_bytes(&compressed_bit_vector, bit_vector.len()).unwrap();
/// 
/// ```
pub fn merkle_root_from_compressed_bytes(compressed_bit_vector: &[u8], expected_uncompressed_size: usize) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let uncompressed_bit_vector = compression::decompress_bit_vector(compressed_bit_vector, expected_uncompressed_size)?;
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

        assert!(merkle_root_from_compressed_bytes(&bit_vector, bit_vector.len()).is_err());

        bit_vector.clear();
        bit_vector.push(0);

        for i in 0..63 {
            bit_vector.push(i);
        }
        
        assert!(merkle_root_from_compressed_bytes(&bit_vector, bit_vector.len() - 1).is_ok());

    }

    #[test]
    fn check_root_hash_computation() {
        let bit_vector_path = "./test/merkle_tree/random_bit_vector.dat";
        let root_hash_path = "./test/merkle_tree/random_bit_vector_root_hash.txt";
        let raw_byte_vector: Vec<u8> = std::fs::read(bit_vector_path).unwrap();
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