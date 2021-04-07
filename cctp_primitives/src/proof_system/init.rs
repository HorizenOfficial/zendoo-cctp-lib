use super::type_mapping::*;

use algebra::curves::tweedle::dee::Affine;
use algebra::{FromBytes, ToBytes};

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
        generators = IPAPC::sample_generators(num_generators);
        let fs = File::create(file_path)?;
        (generators.len() as u32).write(&fs)?;
        generators.write(&fs)?;
    }
    Ok(Arc::new(generators))
}

#[cfg(test)]
mod test {
    use crate::proof_system::type_mapping::*;
    use crate::proof_system::load_generators;
    use std::fs::{File, remove_file};
    use algebra::ToBytes;

    #[test]
    fn check_load_generators() {
        let num_generators = 1 << 10;
        let file_path = "sample_generators";

        println!("Sampling...");

        let generators_init = IPAPC::sample_generators(num_generators);
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