use algebra::{
    curves::tweedle::dee::{
        Affine, Projective,
    },
    FromBytes, ToBytes, to_bytes, AffineCurve, ProjectiveCurve,
};
use digest::Digest;
use blake2::Blake2s;
use rayon::prelude::*;

use std::{
    sync::Arc,
    fs::File,
    path::Path,
    io::{
        Result as IoResult,
        Error as IoError,
        ErrorKind as IoErrorKind,
    }
};

pub const PROTOCOL_NAME: &'static [u8] = b"PC-DL-2020";

pub fn load_generators(num_generators: usize, file_path: &str) -> IoResult<Arc<Vec<Affine>>> {
    let generators;
    if Path::new(file_path).exists() {
        let fs = File::open(file_path)?;
        let count = u32::read(&fs)? as usize;
        if count != num_generators {
            return Err(IoError::new(IoErrorKind::Other, "Generators count mismatch"));
        }
        generators = (0..count).map(|_| Affine::read(&fs).unwrap()).collect();
    } else {
        generators = sample_generators(num_generators);
        let fs = File::create(file_path)?;
        (generators.len() as u32).write(&fs)?;
        generators.write(&fs)?;
    }
    Ok(Arc::new(generators))
}

fn sample_generators(num_generators: usize) -> Vec<Affine> {
    let generators: Vec<_> = (0..num_generators).into_par_iter()
        .map(|i| {
            let i = i as u64;
            let mut hash = Blake2s::digest(&to_bytes![&PROTOCOL_NAME, i].unwrap());
            let mut g = Affine::from_random_bytes(&hash);
            let mut j = 0u64;
            while g.is_none() {
                hash = Blake2s::digest(&to_bytes![&PROTOCOL_NAME, i, j].unwrap());
                g = Affine::from_random_bytes(&hash);
                j += 1;
            }
            let generator = g.unwrap();
            generator.mul_by_cofactor().into_projective()
        })
        .collect();
    Projective::batch_normalization_into_affine(generators)
}

#[cfg(test)]
mod test {
    use crate::proof_system::init::{load_generators, sample_generators};
    use std::fs::{File, remove_file};
    use algebra::ToBytes;

    #[test]
    fn check_load_generators() {
        let num_generators = 1 << 10;
        let file_path = "sample_generators";

        println!("Sampling...");

        let generators_init = sample_generators(num_generators);
        let fs = File::create(file_path).unwrap();
        (generators_init.len() as u32).write(&fs).unwrap();
        generators_init.write(&fs).unwrap();

        println!("Reading...");

        let generators_read = load_generators(num_generators, "sample_generators").unwrap();

        println!("Checking...");

        assert_eq!(generators_init.len(), generators_read.len());
        assert_eq!(generators_init, *generators_read);

        println!("Done!");

        remove_file(file_path).unwrap();
    }
}