//! # Compression
//!
//! `compression` exposes functions to compress and decompress bit vectors.
//! Currently supported compression algorithms are Bzip2 and Gzip.

use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

use bzip2::read::{BzEncoder, BzDecoder};
use flate2::{Compression as GzipCompression, write::GzEncoder, read::GzDecoder};

use crate::{
    printlndbg,
    type_mapping::Error,
};


/// Available compression algorithms.
/// The ffi repr(C) tag has been added here because this enum must be exported from mc-cryptolib.
#[derive(Copy, Clone)]
#[repr(C)]
pub enum CompressionAlgorithm {
    Uncompressed,
    Bzip2,
    Gzip
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == CompressionAlgorithm::Uncompressed as u8 => Ok(CompressionAlgorithm::Uncompressed),
            x if x == CompressionAlgorithm::Bzip2 as u8 => Ok(CompressionAlgorithm::Bzip2),
            x if x == CompressionAlgorithm::Gzip as u8 => Ok(CompressionAlgorithm::Gzip),
            _ => Err(()),
        }
    }
}

/// Compresses `raw_bit vector` (represented as a byte vector)
/// by using the specified compression `algorithm`.
/// The resulting compressed bit vector has an additional first byte
/// representing the algorithm used for the compression process.
///
/// # Examples
///
/// ```
/// use cctp_primitives::bit_vector::compression::*;
///
/// let bit_vector: Vec<u8> = (0..100).collect();
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Uncompressed as u8);
/// assert_eq!(bit_vector.len() + 1, compressed_bit_vector.len());
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Bzip2).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Bzip2 as u8);
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Gzip).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Gzip as u8);
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
/// ```
#[allow(unused_variables)]
pub fn compress_bit_vector(raw_bit_vector: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, Error> {
    let compressed_bit_vector_result;

    printlndbg!("Compressing bit vector...");
    printlndbg!("Algorithm: {}, size: {}, address: {:p}", algorithm as u8, raw_bit_vector.len(), raw_bit_vector);

    printlndbg!("Bit vector content:");
    printlndbg!("{:x?}", raw_bit_vector);


    match algorithm {
        CompressionAlgorithm::Uncompressed => compressed_bit_vector_result = Ok(raw_bit_vector.to_vec()),
        CompressionAlgorithm::Bzip2 => compressed_bit_vector_result = bzip2_compress(raw_bit_vector),
        CompressionAlgorithm::Gzip => compressed_bit_vector_result = gzip_compress(raw_bit_vector),
    }

    if compressed_bit_vector_result.is_ok() {
        let mut compressed_bit_vector = compressed_bit_vector_result.unwrap();
        compressed_bit_vector.insert(0, algorithm as u8);
        compressed_bit_vector.shrink_to_fit();
        return Ok(compressed_bit_vector);
    } else {
        compressed_bit_vector_result
    }
}

/// Decompresses `compressed_bit vector` (represented as a byte vector slice)
/// by using the compression `algorithm` specified as the first byte of the vector.
/// The function requires the resulting vector to have `expected_size` bytes.
///
/// # Errors
/// Returns an error if the decompressed size is different than `expected size` (bytes).
/// 
/// # Examples
///
/// ```
/// use cctp_primitives::bit_vector::compression::*;
///
/// let bit_vector: Vec<u8> = (0..100).collect();
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Uncompressed as u8);
/// assert_eq!(bit_vector.len() + 1, compressed_bit_vector.len());
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Bzip2).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Bzip2 as u8);
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
///
/// let compressed_bit_vector = compress_bit_vector(&bit_vector, CompressionAlgorithm::Gzip).unwrap();
/// assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Gzip as u8);
/// let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, bit_vector.len()).unwrap();
/// assert_eq!(bit_vector, decompressed_bit_vector);
/// ```
#[allow(unused_variables)]
pub fn decompress_bit_vector(compressed_bit_vector: &[u8], expected_size: usize) -> Result<Vec<u8>, Error> {
    decompress_bit_vector_with_opt_checks(compressed_bit_vector, Some(expected_size))
}

#[allow(unused_variables)]
pub fn decompress_bit_vector_without_checks(compressed_bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_bit_vector_with_opt_checks(compressed_bit_vector, None)
}

#[allow(unused_variables)]
fn decompress_bit_vector_with_opt_checks(compressed_bit_vector: &[u8], expected_size_opt: Option<usize>) -> Result<Vec<u8>, Error> {

    printlndbg!("Decompressing bit vector...");
    printlndbg!("Algorithm: {}, size: {}, expected decompressed size: {} (check: {}), address: {:p}",
    compressed_bit_vector[0], compressed_bit_vector.len(),
    expected_size_opt.unwrap_or_default(), expected_size_opt.is_some(), compressed_bit_vector);

    printlndbg!("Bit vector content:");
    printlndbg!("{:x?}", compressed_bit_vector);

    let mut raw_bit_vector_result =  match compressed_bit_vector[0].try_into() {
        Ok(CompressionAlgorithm::Uncompressed) => Ok(compressed_bit_vector[1..].to_vec()),
        Ok(CompressionAlgorithm::Bzip2) => bzip2_decompress(&compressed_bit_vector[1..]),
        Ok(CompressionAlgorithm::Gzip) => gzip_decompress(&compressed_bit_vector[1..]),
        Err(_) => Err("Compression algorithm not supported")?
    }?;

    if expected_size_opt.is_some() {
        let expected_size = expected_size_opt.unwrap();
        if raw_bit_vector_result.len() != expected_size {
            Err(format!("Wrong bit vector size. Expected {} bytes, found {} bytes", expected_size, raw_bit_vector_result.len()))?
        }
    }

    raw_bit_vector_result.shrink_to_fit();
    Ok(raw_bit_vector_result)
}

fn bzip2_compress(bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut compressor = BzEncoder::new(bit_vector, bzip2::Compression::best());
    let mut bzip_compressed = Vec::new();
    compressor.read_to_end(&mut bzip_compressed)?;

    Ok(bzip_compressed)
}

fn bzip2_decompress(compressed_bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut uncompressed_bitvector = Vec::new();
    let mut decompressor = BzDecoder::new(compressed_bit_vector);
    decompressor.read_to_end(&mut uncompressed_bitvector)?;
    
    Ok(uncompressed_bitvector)
}

fn gzip_compress(bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut e = GzEncoder::new(Vec::new(), GzipCompression::best());
    e.write_all(bit_vector)?;
    let result = e.finish()?;

    Ok(result)
}

fn gzip_decompress(compressed_bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut uncompressed_bitvector = Vec::new();
    let mut e = GzDecoder::new(compressed_bit_vector);
    e.read_to_end(&mut uncompressed_bitvector)?;

    return Ok(uncompressed_bitvector);
}

#[cfg(test)]
mod test {

    use super::*;
    use rand::{Rng, SeedableRng};

    fn generate_random_bit_vector(seed: u64) -> Vec<u8> {
        let mut random_generator = rand::rngs::StdRng::seed_from_u64(seed);
        let bit_vector_size: u16 = random_generator.gen();

        let mut bit_vector: Vec<u8> = Vec::with_capacity(bit_vector_size as usize);

        for _ in 0..bit_vector_size {
            bit_vector.push(random_generator.gen());
        }

        bit_vector
    }

    #[test]
    fn empty_bit_vector_compression() {
        let empty_bit_vector: Vec<u8> = Vec::with_capacity(0);

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        assert_eq!(compressed_bit_vector.len(), empty_bit_vector.len() + 1);
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Uncompressed as u8);
        let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Bzip2 as u8);
        let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Gzip as u8);
        let decompressed_bit_vector = decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());
    }

    #[test]
    fn expected_bit_vector_size() {
        let seed: u64 = rand::thread_rng().gen();
        let original_bit_vector: Vec<u8> = generate_random_bit_vector(seed);

        let mut wrong_bit_vector_size: usize = original_bit_vector.len();

        while wrong_bit_vector_size != original_bit_vector.len() {
            wrong_bit_vector_size = rand::thread_rng().gen();
        }

        let compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(), "Decompression error using seed={}", seed);
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(), "Unexpected behavior using seed={}", seed);

        let compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(), "Bzip2 decompression error using seed={}", seed);
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(), "Unexpected Bzip2 behavior using seed={}", seed);

        let compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(), "Gzip decompression error using seed={}", seed);
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(), "Unexpected Gzip behavior using seed={}", seed);
    }

    #[test]
    fn wrong_bit_vector_compression_format() {
        let seed: u64 = rand::thread_rng().gen();
        let original_bit_vector: Vec<u8> = generate_random_bit_vector(seed);

        let mut compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Bzip2 as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        compressed_bit_vector[0] = CompressionAlgorithm::Gzip as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());

        compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Gzip as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());

        compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Bzip2 as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(compressed_bit_vector.len(), compressed_bit_vector.capacity());
    }
}
