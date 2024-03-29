//! # Compression
//!
//! `compression` exposes functions to compress and decompress bit vectors.
//! Currently supported compression algorithms are Bzip2 and Gzip.

use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

use bzip2::read::{BzDecoder, BzEncoder};
use flate2::{read::GzDecoder, write::GzEncoder, Compression as GzipCompression};

use crate::type_mapping::Error;

/// The chunk size used in the decompression functions.
const DECOMPRESSION_CHUNK_SIZE: usize = 1024;

/// The maximum size [bytes] allowed for decompressed buffers.
/// When decompressing, if the size exceeds this threshold, an error is returned.
/// This value is set around to the double of the size limit for uncompressed
/// bit vectors on mainchain side.
const MAX_DECOMPRESSION_SIZE: usize = 1024 * 260; // 260 KB

/// Available compression algorithms.
/// The ffi repr(C) tag has been added here because this enum must be exported from mc-cryptolib.
#[derive(Copy, Clone)]
#[repr(C)]
pub enum CompressionAlgorithm {
    Uncompressed,
    Bzip2,
    Gzip,
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == CompressionAlgorithm::Uncompressed as u8 => {
                Ok(CompressionAlgorithm::Uncompressed)
            }
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
pub fn compress_bit_vector(
    raw_bit_vector: &[u8],
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>, Error> {
    let compressed_bit_vector_result;

    log::debug!("Compressing bit vector...");
    log::debug!(
        "Algorithm: {}, size: {}, address: {:p}",
        algorithm as u8,
        raw_bit_vector.len(),
        raw_bit_vector
    );

    match algorithm {
        CompressionAlgorithm::Uncompressed => {
            compressed_bit_vector_result = Ok(raw_bit_vector.to_vec())
        }
        CompressionAlgorithm::Bzip2 => {
            compressed_bit_vector_result = bzip2_compress(raw_bit_vector)
        }
        CompressionAlgorithm::Gzip => compressed_bit_vector_result = gzip_compress(raw_bit_vector),
    }

    if let Ok(compressed_bit_vector_result) = compressed_bit_vector_result {
        let mut compressed_bit_vector = compressed_bit_vector_result;
        compressed_bit_vector.insert(0, algorithm as u8);
        compressed_bit_vector.shrink_to_fit();
        Ok(compressed_bit_vector)
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
pub fn decompress_bit_vector(
    compressed_bit_vector: &[u8],
    expected_size: usize,
) -> Result<Vec<u8>, Error> {
    decompress_bit_vector_with_opt_checks(compressed_bit_vector, Some(expected_size))
}

pub fn decompress_bit_vector_without_checks(
    compressed_bit_vector: &[u8],
) -> Result<Vec<u8>, Error> {
    decompress_bit_vector_with_opt_checks(compressed_bit_vector, None)
}

fn decompress_bit_vector_with_opt_checks(
    compressed_bit_vector: &[u8],
    expected_size_opt: Option<usize>,
) -> Result<Vec<u8>, Error> {
    log::debug!("Decompressing bit vector...");
    log::debug!(
        "Algorithm: {}, size: {}, expected decompressed size: {:?} (check: {}), address: {:p}",
        compressed_bit_vector[0],
        compressed_bit_vector.len(),
        expected_size_opt,
        expected_size_opt.is_some(),
        compressed_bit_vector
    );

    let mut max_decompressed_size: usize = MAX_DECOMPRESSION_SIZE;
    log::debug!(
        "MAX_DECOMPRESSION_SIZE: {}, expected: {:?}",
        MAX_DECOMPRESSION_SIZE,
        expected_size_opt
    );

    if let Some(expected_size_opt) = expected_size_opt {
        max_decompressed_size = expected_size_opt;

        if max_decompressed_size > MAX_DECOMPRESSION_SIZE {
            Err(format!(
                "The expected uncompressed size {} exceeds the maximum allowed size {}",
                max_decompressed_size, MAX_DECOMPRESSION_SIZE
            ))?
        }
    }

    let mut raw_bit_vector_result = match compressed_bit_vector[0].try_into() {
        Ok(CompressionAlgorithm::Uncompressed) => Ok(compressed_bit_vector[1..].to_vec()),
        Ok(CompressionAlgorithm::Bzip2) => {
            bzip2_decompress(&compressed_bit_vector[1..], max_decompressed_size)
        }
        Ok(CompressionAlgorithm::Gzip) => {
            gzip_decompress(&compressed_bit_vector[1..], max_decompressed_size)
        }
        Err(_) => Err("Compression algorithm not supported")?,
    }?;

    log::debug!("Decompressed size: {}", raw_bit_vector_result.len());

    if let Some(expected_size_opt) = expected_size_opt {
        let expected_size = expected_size_opt;
        if raw_bit_vector_result.len() != expected_size {
            Err(format!(
                "Wrong bit vector size. Expected {} bytes, found {} bytes",
                expected_size,
                raw_bit_vector_result.len()
            ))?
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

fn bzip2_decompress(
    compressed_bit_vector: &[u8],
    max_decompressed_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut uncompressed_bitvector = Vec::with_capacity(max_decompressed_size);
    let mut decompressor = BzDecoder::new(compressed_bit_vector);
    let mut fixed_array = [0; DECOMPRESSION_CHUNK_SIZE];

    // Uncompress data in chunks of "DECOMPRESSION_CHUNK_SIZE" bytes, so that the processing can be stopped
    // as soon as the uncompressed size exceeds the "max_decompressed_size" threshold.
    loop {
        let read_size = decompressor.read(&mut fixed_array)?;
        uncompressed_bitvector.extend_from_slice(&fixed_array[..read_size]);

        if uncompressed_bitvector.len() > max_decompressed_size {
            Err(format!(
                "Max decompressed size {} exceeded {} while processing [Bzip2]",
                max_decompressed_size,
                uncompressed_bitvector.len()
            ))?
        }
        if read_size == 0 {
            break;
        }
    }

    Ok(uncompressed_bitvector)
}

fn gzip_compress(bit_vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut e = GzEncoder::new(Vec::new(), GzipCompression::best());
    e.write_all(bit_vector)?;
    let result = e.finish()?;

    Ok(result)
}

fn gzip_decompress(
    compressed_bit_vector: &[u8],
    max_decompressed_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut uncompressed_bitvector = Vec::with_capacity(max_decompressed_size);
    let mut decompressor = GzDecoder::new(compressed_bit_vector);
    let mut fixed_array = [0; DECOMPRESSION_CHUNK_SIZE];

    // Uncompress data in chunks of "DECOMPRESSION_CHUNK_SIZE" bytes, so that the processing can be stopped
    // as soon as the uncompressed size exceeds the "max_decompressed_size" threshold.
    loop {
        let read_size = decompressor.read(&mut fixed_array)?;
        uncompressed_bitvector.extend_from_slice(&fixed_array[..read_size]);

        if uncompressed_bitvector.len() > max_decompressed_size {
            Err(format!(
                "Max decompressed size {} exceeded {} while processing [Gzip]",
                max_decompressed_size,
                uncompressed_bitvector.len()
            ))?
        }
        if read_size == 0 {
            break;
        }
    }

    Ok(uncompressed_bitvector)
}

#[cfg(test)]
mod test {

    use super::*;
    use rand::{Rng, SeedableRng};

    fn generate_random_bit_vector(seed: u64) -> Vec<u8> {
        let mut random_generator = rand::rngs::StdRng::seed_from_u64(seed);
        let bit_vector_size: u32 = random_generator.gen_range(0..MAX_DECOMPRESSION_SIZE as u32);

        let mut bit_vector: Vec<u8> = Vec::with_capacity(bit_vector_size as usize);

        for _ in 0..bit_vector_size {
            bit_vector.push(random_generator.gen());
        }

        bit_vector
    }

    #[test]
    fn empty_bit_vector_compression() {
        let empty_bit_vector: Vec<u8> = Vec::with_capacity(0);

        let compressed_bit_vector =
            compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        assert_eq!(compressed_bit_vector.len(), empty_bit_vector.len() + 1);
        assert_eq!(
            compressed_bit_vector[0],
            CompressionAlgorithm::Uncompressed as u8
        );
        let decompressed_bit_vector =
            decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );

        let compressed_bit_vector =
            compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Bzip2 as u8);
        let decompressed_bit_vector =
            decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );

        let compressed_bit_vector =
            compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Gzip as u8);
        let decompressed_bit_vector =
            decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap();
        assert_eq!(decompressed_bit_vector, empty_bit_vector);
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );
    }

    #[test]
    fn expected_bit_vector_size() {
        let seed: u64 = rand::thread_rng().gen();
        let original_bit_vector: Vec<u8> = generate_random_bit_vector(seed);

        let compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(),
            "Decompression error using seed={}",
            seed
        );
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(),
            "Unexpected behavior using seed={}",
            seed
        );

        let compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(),
            "Bzip2 decompression error using seed={}",
            seed
        );
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(),
            "Unexpected Bzip2 behavior using seed={}",
            seed
        );

        let compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_ok(),
            "Gzip decompression error using seed={}",
            seed
        );
        assert!(
            decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len() + 1).is_err(),
            "Unexpected Gzip behavior using seed={}",
            seed
        );
    }

    #[test]
    fn wrong_bit_vector_compression_format() {
        let seed: u64 = rand::thread_rng().gen();
        let original_bit_vector: Vec<u8> = generate_random_bit_vector(seed);

        let mut compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Uncompressed).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Bzip2 as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        compressed_bit_vector[0] = CompressionAlgorithm::Gzip as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );

        compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Gzip as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );

        compressed_bit_vector =
            compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Bzip2 as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
        assert_eq!(
            compressed_bit_vector.len(),
            compressed_bit_vector.capacity()
        );
    }

    /// Checks that the decompression function doesn't crash when provided with a small compressed bit vector
    /// that once decompressed "expands" to a huge size.
    #[test]
    fn huge_bit_vector_decompression() {
        // The input file contains a compressed bit vector of around 10 KB whose decompressed size is around 16 GB.
        let mut compressed_bit_vector =
            std::fs::read("./test/compression/16gb_bitvector_bzip2.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_err(),
            "Bzip2 error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_err(),
            "Bzip2 error"
        );

        // The input file contains a compressed bit vector of around 10 KB whose decompressed size is around 10 MB.
        compressed_bit_vector =
            std::fs::read("./test/compression/10mb_bitvector_gzip.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_err(),
            "Gzip error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_err(),
            "Gzip error"
        );

        // The input file contains a compressed bit vector whose decompressed size is 260 KB plus 1 byte.
        compressed_bit_vector =
            std::fs::read("./test/compression/160kb_plus_one_bitvector_bzip2.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE + 1)
            )
            .is_err(),
            "Bzip2 error"
        );
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_err(),
            "Bzip2 error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_err(),
            "Bzip2 error"
        );

        // The input file contains a compressed bit vector whose decompressed size is 260 KB plus 1 byte.
        compressed_bit_vector =
            std::fs::read("./test/compression/160kb_plus_one_bitvector_gzip.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE + 1)
            )
            .is_err(),
            "Gzip error"
        );
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_err(),
            "Gzip error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_err(),
            "Gzip error"
        );

        // The input file contains a compressed bit vector whose decompressed size is 260 KB.
        compressed_bit_vector =
            std::fs::read("./test/compression/160kb_bitvector_bzip2.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_ok(),
            "Bzip2 error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_ok(),
            "Bzip2 error"
        );

        // The input file contains a compressed bit vector whose decompressed size is 260 KB.
        compressed_bit_vector =
            std::fs::read("./test/compression/160kb_bitvector_gzip.dat").unwrap();
        assert!(
            decompress_bit_vector_with_opt_checks(
                &compressed_bit_vector,
                Some(MAX_DECOMPRESSION_SIZE)
            )
            .is_ok(),
            "Gzip error"
        );
        assert!(
            decompress_bit_vector_without_checks(&compressed_bit_vector).is_ok(),
            "Gzip error"
        );
    }
}
