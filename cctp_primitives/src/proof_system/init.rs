use super::type_mapping::*;

use algebra::{serialize::*, AffineCurve};

use poly_commit::PolynomialCommitment;
use poly_commit::ipa_pc::{CommitterKey, InnerProductArgPC};

use lazy_static::lazy_static;

use std::sync::RwLock;
use std::fs::File;
use std::path::Path;
use blake2::Blake2s;

lazy_static! {
    static ref G1_COMMITTER_KEY: RwLock<Option<CommitterKey<G1Affine>>> = RwLock::new(None);
}

lazy_static! {
    static ref G2_COMMITTER_KEY: RwLock<Option<CommitterKey<G2Affine>>> = RwLock::new(None);
}

pub fn load_g1_commiter_key(max_degree: usize, file_path: &str) -> Result<(), SerializationError> {

    match load_generators::<G1Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            G1_COMMITTER_KEY.write().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        Err(e) => Err(e)
    }
}

pub fn load_g2_commiter_key(max_degree: usize, file_path: &str) -> Result<(), SerializationError> {

    match load_generators::<G2Affine>(max_degree, file_path) {
        Ok(loaded_key) => {
            G2_COMMITTER_KEY.write().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        Err(e) => Err(e)
    }
}

fn load_generators<G: AffineCurve>(max_degree: usize, file_path: &str) -> Result<CommitterKey<G>, SerializationError> {

    let mut pk: CommitterKey<G>;

    if Path::new(file_path).exists() {
        // Try to read the CommitterKey from file
        let fs = File::open(file_path).map_err(|e| SerializationError::IoError(e))?;
        pk = CanonicalDeserialize::deserialize(fs)?;
        if pk.max_degree == max_degree {
            return Ok(pk)
        }
    }

    // File doesn't exist or the pk is smaller than the requested max_degree:
    // generate the committer key and save it to file
    let pp = InnerProductArgPC::<G, Blake2s>::setup(max_degree)
        .map_err(|_| SerializationError::InvalidData)?;
    let (ck, _) = InnerProductArgPC::<G, Blake2s>::trim(&pp, max_degree)
        .map_err(|_| SerializationError::InvalidData)?;
    pk = ck;
    let fs = File::create(file_path).map_err(|e| SerializationError::IoError(e))?;
    CanonicalSerialize::serialize(&pk, fs)?;

    // Return the read/generated committer key
    Ok(pk)
}

#[cfg(test)]
mod test {
    use super::{G1_COMMITTER_KEY, G2_COMMITTER_KEY};

    use crate::proof_system::{load_g1_commiter_key, load_g2_commiter_key};
    use crate::proof_system::type_mapping::*;

    use algebra::serialize::*;

    use poly_commit::ipa_pc::InnerProductArgPC;
    use poly_commit::PolynomialCommitment;

    use blake2::Blake2s;

    use std::fs::{File, remove_file};

    #[test]
    fn check_load_g1_commiter_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk_g1";

        let pp = InnerProductArgPC::<G1Affine, Blake2s>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G1Affine, Blake2s>::trim(&pp, max_degree).unwrap();

        let fs = File::create(&file_path).unwrap();
        CanonicalSerialize::serialize(&pk, fs).unwrap();

        load_g1_commiter_key(max_degree, file_path).unwrap();

        let ck = G1_COMMITTER_KEY.read().unwrap();

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

        let pp = InnerProductArgPC::<G2Affine, Blake2s>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G2Affine, Blake2s>::trim(&pp, max_degree).unwrap();

        let fs = File::create(&file_path).unwrap();
        CanonicalSerialize::serialize(&pk, fs).unwrap();

        load_g2_commiter_key(max_degree, file_path).unwrap();

        let ck = G2_COMMITTER_KEY.read().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);

        remove_file(file_path).unwrap();
    }
}