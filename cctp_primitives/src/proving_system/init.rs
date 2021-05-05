use crate::type_mapping::*;

use algebra::{AffineCurve, serialize::*};

use poly_commit::PolynomialCommitment;
use poly_commit::ipa_pc::{CommitterKey, InnerProductArgPC};

use crate::proving_system::error::ProvingSystemError;

use lazy_static::lazy_static;

use std::sync::{
    RwLock, RwLockReadGuard
};
use std::fs::File;
use std::path::Path;

// We need a mutable static variable to store the committer key.
// To avoid the usage of unsafe code blocks (required when mutating a static variable)
// we use a lazy_static; however, the lazy_static requires its argument to be thread-safe
// (even if the variable is accessed in a single-threaded environment): that's why we
// additionally wrapped the committer key in a RwLock.

lazy_static! {
    pub static ref G1_COMMITTER_KEY: RwLock<Option<CommitterKeyG1>> = RwLock::new(None);
}

lazy_static! {
    pub static ref G2_COMMITTER_KEY: RwLock<Option<CommitterKeyG2>> = RwLock::new(None);
}

/// Load G1CommitterKey of degree `max_degree` from `file_path` if it exists, otherwise create it,
/// load it, and save it into a new file at `file_path`.
pub fn load_g1_committer_key(max_degree: usize, file_path: &str) -> Result<(), SerializationError> {

    match load_generators::<G1>(max_degree, file_path) {
        // Generation/Loading successfull, assign the key to the lazy_static
        Ok(loaded_key) => {
            G1_COMMITTER_KEY.write().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        // Error while generating/reading file/writing file
        Err(e) => Err(e)
    }
}

/// Load G2CommitterKey of degree `max_degree` from `file_path` if it exists, otherwise create it,
/// load it, and save it into a new file at `file_path`.
pub fn load_g2_committer_key(max_degree: usize, file_path: &str) -> Result<(), SerializationError> {

    match load_generators::<G2>(max_degree, file_path) {
        // Generation/Loading successfull, assign the key to the lazy_static
        Ok(loaded_key) => {
            G2_COMMITTER_KEY.write().as_mut().unwrap().replace(loaded_key);
            Ok(())
        },
        // Error while generating/reading file/writing file
        Err(e) => Err(e)
    }
}

/// Return a RwLockGuard containing the G1CommitterKey, if G1CommitterKey has been initialized,
/// otherwise return Error.
pub fn get_g1_committer_key<'a>() -> Result<RwLockReadGuard<'a, Option<CommitterKeyG1>>, ProvingSystemError> {
    let ck_g1_guard = G1_COMMITTER_KEY.read()
        .map_err(|_| ProvingSystemError::Other("Failed to acquire lock for G1 Committer Key".to_owned()))?;
    if ck_g1_guard.is_some() {
        Ok(ck_g1_guard)
    } else {
        Err(ProvingSystemError::CommitterKeyNotInitialized)
    }
}

/// Return a RwLockGuard containing the G2CommitterKey, if G2CommitterKey has been initialized,
/// otherwise return Error.
pub fn get_g2_committer_key<'a>() -> Result<RwLockReadGuard<'a, Option<CommitterKeyG2>>, ProvingSystemError> {
    let ck_g2_guard = G2_COMMITTER_KEY.read()
        .map_err(|_| ProvingSystemError::Other("Failed to acquire lock for G2 Committer Key".to_owned()))?;
    if ck_g2_guard.is_some() {
        Ok(ck_g2_guard)
    } else {
        Err(ProvingSystemError::CommitterKeyNotInitialized)
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
    let pp = InnerProductArgPC::<G, Digest>::setup(max_degree)
        .map_err(|_| SerializationError::InvalidData)?;
    let (ck, _) = InnerProductArgPC::<G, Digest>::trim(&pp, max_degree)
        .map_err(|_| SerializationError::InvalidData)?;
    pk = ck;
    let fs = File::create(file_path).map_err(|e| SerializationError::IoError(e))?;
    CanonicalSerialize::serialize(&pk, fs)?;

    // Return the read/generated committer key
    Ok(pk)
}

#[cfg(test)]
mod test {
    use super::*;

    use poly_commit::ipa_pc::InnerProductArgPC;
    use poly_commit::PolynomialCommitment;

    use std::fs::{File, remove_file};
    use serial_test::serial;

    #[test]
    #[serial]
    fn check_load_g1_committer_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk_g1";

        let pp = InnerProductArgPC::<G1, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G1, Digest>::trim(&pp, max_degree).unwrap();

        let fs = File::create(file_path).unwrap();
        CanonicalSerialize::serialize(&pk, fs).unwrap();

        load_g1_committer_key(max_degree, file_path).unwrap();

        let ck = get_g1_committer_key().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);

        remove_file(file_path).unwrap();
    }

    #[test]
    #[serial]
    fn check_load_g2_committer_key() {
        let max_degree = 1 << 10;
        let file_path = "sample_pk_g2";

        let pp = InnerProductArgPC::<G2, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G2, Digest>::trim(&pp, max_degree).unwrap();

        let fs = File::create(file_path).unwrap();
        CanonicalSerialize::serialize(&pk, fs).unwrap();

        load_g2_committer_key(max_degree, file_path).unwrap();

        let ck = get_g2_committer_key().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);

        remove_file(file_path).unwrap();
    }
}