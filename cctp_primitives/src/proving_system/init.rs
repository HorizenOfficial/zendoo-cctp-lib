use crate::type_mapping::*;

use algebra::{AffineCurve, serialize::*};

use poly_commit::PolynomialCommitment;
use poly_commit::ipa_pc::{CommitterKey, InnerProductArgPC};

use crate::proving_system::error::ProvingSystemError;

use lazy_static::lazy_static;

use std::sync::{
    RwLock, RwLockReadGuard
};

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

/// Generate G1CommitterKey and store it in memory.
/// The parameter `max_degree` is required in order to derive a unique hash for the key itself.
pub fn load_g1_committer_key(
    max_degree: usize,
    supported_degree: usize,
) -> Result<(), SerializationError>
{
    match load_generators::<G1>(max_degree, supported_degree) {
        // Generation/Loading successfull, assign the key to the lazy_static
        Ok(loaded_key) => {
            G1_COMMITTER_KEY.write().as_mut().map_err(|_| {
                SerializationError::IoError(
                    std::io::Error::new(std::io::ErrorKind::Other, "G1_COMMITTER_KEY write failed")
                )
            })?.replace(loaded_key);
            Ok(())
        },
        // Error while generating/reading file/writing file
        Err(e) => Err(e)
    }
}

/// Generate G2CommitterKey and store it in memory.
/// The parameter `max_degree` is required in order to derive a unique hash for the key itself.
pub fn load_g2_committer_key(
    max_degree: usize,
    supported_degree: usize,
) -> Result<(), SerializationError>
{
    match load_generators::<G2>(max_degree, supported_degree) {
        // Generation/Loading successful, assign the key to the lazy_static
        Ok(loaded_key) => {
            G2_COMMITTER_KEY.write().as_mut().map_err(|_| {
                SerializationError::IoError(
                    std::io::Error::new(std::io::ErrorKind::Other, "G2_COMMITTER_KEY write failed")
                )
            })?.replace(loaded_key);
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

fn load_generators<G: AffineCurve>(
    max_degree: usize,
    supported_degree: usize,
) -> Result<CommitterKey<G>, SerializationError>
{
    let pp = InnerProductArgPC::<G, Digest>::setup(max_degree)
        .map_err(|_| SerializationError::InvalidData)?;
    let (ck, _) = InnerProductArgPC::<G, Digest>::trim(&pp, supported_degree)
        .map_err(|_| SerializationError::InvalidData)?;

    // Return the read/generated committer key
    Ok(ck)
}

#[cfg(test)]
mod test {
    use super::*;

    use poly_commit::ipa_pc::InnerProductArgPC;
    use poly_commit::PolynomialCommitment;
    use serial_test::serial;

    #[test]
    #[serial]
    fn check_load_g1_committer_key() {
        let max_degree = 1 << 10;
        let supported_degree = 1 << 9;

        let pp = InnerProductArgPC::<G1, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G1, Digest>::trim(&pp, supported_degree).unwrap();

        load_g1_committer_key(max_degree, supported_degree).unwrap();

        let ck = get_g1_committer_key().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);
        assert_eq!(pk.hash, ck.hash);
        assert_eq!(pp.hash, ck.hash);
    }

    #[test]
    #[serial]
    fn check_load_g2_committer_key() {
        let max_degree = 1 << 10;
        let supported_degree = 1 << 9;

        let pp = InnerProductArgPC::<G2, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G2, Digest>::trim(&pp, supported_degree).unwrap();

        load_g2_committer_key(max_degree, supported_degree).unwrap();

        let ck = get_g2_committer_key().unwrap();

        assert!(ck.is_some());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);
        assert_eq!(pk.hash, ck.hash);
        assert_eq!(pp.hash, ck.hash);
    }
}