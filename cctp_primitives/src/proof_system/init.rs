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
    static ref G1_COMMITTER_KEY: Mutex<Option<CommitterKey<G1Affine>>> = Mutex::new(None);
}

lazy_static! {
    static ref G2_COMMITTER_KEY: Mutex<Option<CommitterKey<G2Affine>>> = Mutex::new(None);
}

pub fn load_g1_commiter_key(max_degree: usize, file_path: &str) -> IoResult<()> {

    match load_generators::<G1Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            G1_COMMITTER_KEY.lock().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        Err(e) => Err(e)
    }
}

pub fn load_g2_commiter_key(max_degree: usize, file_path: &str) -> IoResult<()> {

    match load_generators::<G2Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            G2_COMMITTER_KEY.lock().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        Err(e) => Err(e)
    }
}

fn load_generators<G: AffineCurve>(max_degree: usize, file_path: &str) -> IoResult<CommitterKey<G>> {

    let mut pk;

    if Path::new(file_path).exists() {
        let fs = File::open(file_path)?;
        pk = CommitterKey::<G>::read(&fs)?;
        if pk.max_degree == max_degree {
            return Ok(pk);
        }
    }

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
        let file_path = "sample_pk_g1";

        let pp = InnerProductArgPC::<G1Affine, Blake2s>::setup(max_degree, &mut thread_rng()).unwrap();
        let (pk, _) = InnerProductArgPC::<G1Affine, Blake2s>::trim(&pp, max_degree, 0, None).unwrap();

        let fs = File::create(file_path).unwrap();
        pk.write(&fs).unwrap();

        load_g1_commiter_key(max_degree, file_path).unwrap();

        let ck = G1_COMMITTER_KEY.lock().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);

        remove_file(file_path).unwrap();
    }

    #[test]
    fn check_load_g2_commiter_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk_g2";

        let pp = InnerProductArgPC::<G2Affine, Blake2s>::setup(max_degree, &mut thread_rng()).unwrap();
        let (pk, _) = InnerProductArgPC::<G2Affine, Blake2s>::trim(&pp, max_degree, 0, None).unwrap();

        let fs = File::create(file_path).unwrap();
        pk.write(&fs).unwrap();

        load_g2_commiter_key(max_degree, file_path).unwrap();

        let ck = G2_COMMITTER_KEY.lock().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);

        remove_file(file_path).unwrap();
    }
}