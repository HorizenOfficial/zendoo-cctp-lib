use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

use bzip2::read::{BzEncoder, BzDecoder};
use flate2::{Compression as GzipCompression, write::GzEncoder, read::GzDecoder};

use crate::{ printdbg, printlndbg};

type Error = Box<dyn std::error::Error>;

#[derive(Copy, Clone)]
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

#[allow(unused_variables)]
pub fn compress_bit_vector(raw_bit_vector: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, Error> {
    let compressed_bit_vector_result;

    printlndbg!("Compressing bit vector...");
    printlndbg!("Algorithm: {}, size: {}, address: {:p}", algorithm as u8, raw_bit_vector.len(), raw_bit_vector);

    printlndbg!("Bit vector content:");

    raw_bit_vector.iter().for_each(|byte| printdbg!("|{}", byte));

    printlndbg!("|");

    match algorithm {
        CompressionAlgorithm::Uncompressed => compressed_bit_vector_result = Ok(raw_bit_vector.to_vec()),
        CompressionAlgorithm::Bzip2 => compressed_bit_vector_result = bzip2_compress(raw_bit_vector),
        CompressionAlgorithm::Gzip => compressed_bit_vector_result = gzip_compress(raw_bit_vector),
    }

    if compressed_bit_vector_result.is_ok() {
        let mut compressed_bit_vector = compressed_bit_vector_result.unwrap();
        compressed_bit_vector.insert(0, algorithm as u8);

        return Ok(compressed_bit_vector);
    }

    compressed_bit_vector_result
}

#[allow(unused_variables)]
pub fn decompress_bit_vector(compressed_bit_vector: &[u8], expected_size: usize) -> Result<Vec<u8>, Error> {
    
    printlndbg!("Decompressing bit vector...");
    printlndbg!("Algorithm: {}, size: {}, expected decompressed size: {}, address: {:p}", compressed_bit_vector[0], compressed_bit_vector.len(), expected_size, compressed_bit_vector);

    printlndbg!("Bit vector content:");

    compressed_bit_vector.iter().for_each(|byte| printdbg!("|{}", byte));

    printlndbg!("|");
        
    let raw_bit_vector_result =  match compressed_bit_vector[0].try_into() {
        Ok(CompressionAlgorithm::Uncompressed) => Ok(compressed_bit_vector[1..].to_vec()),
        Ok(CompressionAlgorithm::Bzip2) => bzip2_decompress(&compressed_bit_vector[1..]),
        Ok(CompressionAlgorithm::Gzip) => gzip_decompress(&compressed_bit_vector[1..]),
        Err(_) => Err("Compression algorithm not supported")?
    }?;

    if raw_bit_vector_result.len() != expected_size {
        Err(format!("Wrong bit vector size. Expected {} bytes, found {} bytes", expected_size, raw_bit_vector_result.len()))?
    }

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
        assert_eq!(decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap(), empty_bit_vector);

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Bzip2 as u8);
        assert_eq!(decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap(), empty_bit_vector);

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        assert!(compressed_bit_vector.len() > empty_bit_vector.len());
        assert_eq!(compressed_bit_vector[0], CompressionAlgorithm::Gzip as u8);
        assert_eq!(decompress_bit_vector(&compressed_bit_vector, empty_bit_vector.len()).unwrap(), empty_bit_vector);
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

        compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Bzip2).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Gzip as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());

        compressed_bit_vector = compress_bit_vector(&original_bit_vector, CompressionAlgorithm::Gzip).unwrap();
        compressed_bit_vector[0] = CompressionAlgorithm::Bzip2 as u8;
        assert!(decompress_bit_vector(&compressed_bit_vector, original_bit_vector.len()).is_err());
    }
}