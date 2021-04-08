use super::type_mapping::*;

use algebra::{FromBytes, ToBytes, AffineCurve};

use poly_commit::PolynomialCommitment;
use poly_commit::ipa_pc::{CommitterKey, InnerProductArgPC};

use lazy_static::lazy_static;

use std::sync::Mutex;
use std::fs::File;
use std::path::Path;
use std::io::{
    Result as IoResult,
    Error as IoError,
    ErrorKind as IoErrorKind,
};

use blake2::Blake2s;
use rand::thread_rng;

lazy_static! {
    static ref G1_COMMITTER_KEY: Mutex<CommitterKey<G1Affine>> = Mutex::new(CommitterKey::<G1Affine>::default());
}

lazy_static! {
    static ref G2_COMMITTER_KEY: Mutex<CommitterKey<G2Affine>> = Mutex::new(CommitterKey::<G2Affine>::default());
}

pub fn load_g1_commiter_key(max_degree: usize, file_path: &str) -> IoResult<CommitterKey<G1Affine>> {

    let mut key = G1_COMMITTER_KEY.lock().unwrap();

    if key.max_degree == max_degree {
        return Ok((*key).clone());
    }

    match load_generators::<G1Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            key.clone_from(&loaded_key);
            Ok((*key).clone())
        },
        Err(e) => {
            Err(e)
        }
    }
}

pub fn load_g2_commiter_key(max_degree: usize, file_path: &str) -> IoResult<CommitterKey<G2Affine>> {

    let mut key = G2_COMMITTER_KEY.lock().unwrap();

    if key.max_degree == max_degree {
        return Ok((*key).clone());
    }

    match load_generators::<G2Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            key.clone_from(&loaded_key);
            Ok((*key).clone())
        },
        Err(e) => {
            Err(e)
        }
    }
}

fn load_generators<G: AffineCurve>(max_degree: usize, file_path: &str) -> IoResult<CommitterKey<G>> {

    let pk;

    if Path::new(file_path).exists() {
        let fs = File::open(file_path)?;
        pk = CommitterKey::<G>::read(&fs)?;
    } else {
        let pp = match InnerProductArgPC::<G, Blake2s>::setup(max_degree, &mut thread_rng()) {
            Ok(pp) => pp,
            Err(e) => {
                return Err(IoError::new(IoErrorKind::Other, e));
            }
        };
        pk = match InnerProductArgPC::<G, Blake2s>::trim(&pp, max_degree, 0, None) {
            Ok((pk, _)) => pk,
            Err(e) => {
                return Err(IoError::new(IoErrorKind::Other, e));
            }
        };
        let fs = File::create(file_path)?;
        pk.write(&fs)?;
    }

    Ok(pk)
}

#[cfg(test)]
mod test {
    use super::{G1_COMMITTER_KEY, G2_COMMITTER_KEY};

    use crate::proof_system::{load_g1_commiter_key, load_g2_commiter_key};
    use crate::proof_system::type_mapping::*;

    use algebra::ToBytes;

    use poly_commit::ipa_pc::InnerProductArgPC;
    use poly_commit::PolynomialCommitment;

    use rand::thread_rng;
    use blake2::Blake2s;

    use std::fs::{File, remove_file};

    #[test]
    fn check_load_g1_commiter_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk";

        let pp = InnerProductArgPC::<G1Affine, Blake2s>::setup(max_degree, &mut thread_rng()).unwrap();
        let (pk, _) = InnerProductArgPC::<G1Affine, Blake2s>::trim(&pp, max_degree, 0, None).unwrap();

        let fs = File::create(file_path).unwrap();
        pk.write(&fs).unwrap();

        let loaded_pk = load_g1_commiter_key(max_degree, file_path).unwrap();

        assert_eq!(pk.comm_key, loaded_pk.comm_key);
        assert_eq!(pk.h, loaded_pk.h);
        assert_eq!(pk.s, loaded_pk.s);
        assert_eq!(pk.max_degree, loaded_pk.max_degree);

        assert_eq!(pk.comm_key, G1_COMMITTER_KEY.lock().unwrap().comm_key);
        assert_eq!(pk.h, G1_COMMITTER_KEY.lock().unwrap().h);
        assert_eq!(pk.s, G1_COMMITTER_KEY.lock().unwrap().s);
        assert_eq!(pk.max_degree, G1_COMMITTER_KEY.lock().unwrap().max_degree);

        remove_file(file_path).unwrap();
    }

    #[test]
    fn check_load_g2_commiter_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk";

        let pp = InnerProductArgPC::<G2Affine, Blake2s>::setup(max_degree, &mut thread_rng()).unwrap();
        let (pk, _) = InnerProductArgPC::<G2Affine, Blake2s>::trim(&pp, max_degree, 0, None).unwrap();

        let fs = File::create(file_path).unwrap();
        pk.write(&fs).unwrap();

        let loaded_pk = load_g2_commiter_key(max_degree, file_path).unwrap();

        assert_eq!(pk.comm_key, loaded_pk.comm_key);
        assert_eq!(pk.h, loaded_pk.h);
        assert_eq!(pk.s, loaded_pk.s);
        assert_eq!(pk.max_degree, loaded_pk.max_degree);

        assert_eq!(pk.comm_key, G2_COMMITTER_KEY.lock().unwrap().comm_key);
        assert_eq!(pk.h, G2_COMMITTER_KEY.lock().unwrap().h);
        assert_eq!(pk.s, G2_COMMITTER_KEY.lock().unwrap().s);
        assert_eq!(pk.max_degree, G2_COMMITTER_KEY.lock().unwrap().max_degree);

        remove_file(file_path).unwrap();
    }
}