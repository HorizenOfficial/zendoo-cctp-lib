use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

use bzip2::read::{BzEncoder, BzDecoder};
use flate2::{Compression as GzipCompression, write::GzEncoder, read::GzDecoder};

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

pub fn compress_bit_vector(raw_bit_vector: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, &str> {
    let mut compressed_bit_vector;

    match algorithm {
        CompressionAlgorithm::Uncompressed => compressed_bit_vector = raw_bit_vector.to_vec(),
        CompressionAlgorithm::Bzip2 => compressed_bit_vector = bzip2_compress(raw_bit_vector),
        CompressionAlgorithm::Gzip => compressed_bit_vector = gzip_compress(raw_bit_vector),
    }

    compressed_bit_vector.insert(0, algorithm as u8);
    Ok(compressed_bit_vector)
}

pub fn decompress_bit_vector(compressed_bit_vector: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
    let raw_bit_vector;
        
    match compressed_bit_vector[0].try_into() {
        Ok(CompressionAlgorithm::Uncompressed) => raw_bit_vector = compressed_bit_vector[1..].to_vec(),
        Ok(CompressionAlgorithm::Bzip2) => raw_bit_vector = bzip2_decompress(&compressed_bit_vector[1..]),
        Ok(CompressionAlgorithm::Gzip) => raw_bit_vector = gzip_decompress(&compressed_bit_vector[1..]),
        Err(_) => return Err(String::from("Compression algorithm not supported"))
    }

    if raw_bit_vector.len() != expected_size {
        return Err(format!("Wrong bit vector size. Expected {} bytes, found {} bytes", expected_size, raw_bit_vector.len()));
    }

    Ok(raw_bit_vector)
}

fn bzip2_compress(bit_vector: &[u8]) -> Vec<u8> {
    let mut compressor = BzEncoder::new(bit_vector, bzip2::Compression::best());
    let mut bzip_compressed = Vec::new();
    compressor.read_to_end(&mut bzip_compressed).unwrap();
    bzip_compressed
}

fn bzip2_decompress(compressed_bit_vector: &[u8]) -> Vec<u8> {
    let mut uncompressed_bitvector = Vec::new();
    let mut decompressor = BzDecoder::new(compressed_bit_vector);
    decompressor.read_to_end(&mut uncompressed_bitvector).unwrap();
    uncompressed_bitvector
}

fn gzip_compress(bit_vector: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), GzipCompression::best());
    e.write_all(bit_vector).unwrap();
    e.finish().unwrap()
}

fn gzip_decompress(compressed_bit_vector: &[u8]) -> Vec<u8> {
    let mut uncompressed_bitvector = Vec::new();
    let mut e = GzDecoder::new(compressed_bit_vector);
    e.read_to_end(&mut uncompressed_bitvector).unwrap();
    uncompressed_bitvector
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn check_compression_algorithm() {
        let empty_bit_vector: Vec<u8> = Vec::with_capacity(0);

        let compressed_bit_vector = compress_bit_vector(&empty_bit_vector, CompressionAlgorithm::Uncompressed);
        assert_eq!(compressed_bit_vector.unwrap().len(), 1);
    }

}