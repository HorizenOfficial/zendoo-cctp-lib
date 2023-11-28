use crate::proving_system::error::ProvingSystemError;
use crate::type_mapping::*;
use algebra::{serialize::*, AffineCurve};
use lazy_static::lazy_static;
use poly_commit::ipa_pc::{InnerProductArgPC, UniversalParams};
use poly_commit::{PCUniversalParams, PolynomialCommitment};
use std::sync::RwLock;

// We need a mutable static variable to store the committer key.
// To avoid the usage of unsafe code blocks (required when mutating a static variable)
// we use a lazy_static; however, the lazy_static requires its argument to be thread-safe
// (even if the variable is accessed in a single-threaded environment): that's why we
// additionally wrapped the committer key in a RwLock.

lazy_static! {
    pub static ref G1_UNIVERSAL_PARAMS: RwLock<Option<UniversalParams<G1>>> = RwLock::new(None);
}

lazy_static! {
    pub static ref G2_UNIVERSAL_PARAMS: RwLock<Option<UniversalParams<G2>>> = RwLock::new(None);
}

/// Generate `G1_UNIVERSAL_PARAMETERS` and store it in memory.
/// This function should be called exactly once during program execution and before any call to
/// `get_g1_committer_key()`. Further calls leave `G1_UNIVERSAL_PARAMETERS` unchanged and return an
/// error instead.
/// The parameter `max_degree` is required in order to derive a unique hash for the key itself.
pub fn load_g1_committer_key(max_degree: usize) -> Result<(), SerializationError> {
    {
        let pp_g1_guard = G1_UNIVERSAL_PARAMS.read().map_err(|_| {
            SerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to acquire lock for G1_UNIVERSAL_PARAMS".to_owned(),
            ))
        })?;
        if pp_g1_guard.is_some() {
            return Err(SerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "G1_UNIVERSAL_PARAMS has already been generated",
            )));
        }
    }
    log::info!("Generating G1 Dlog Keys of degree: {}", max_degree);
    match load_universal_params::<G1>(max_degree) {
        // Generation/Loading successfull, assign the key to the lazy_static
        Ok(loaded_params) => {
            G1_UNIVERSAL_PARAMS
                .write()
                .as_mut()
                .map_err(|_| {
                    SerializationError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "G1_UNIVERSAL_PARAMS write failed",
                    ))
                })?
                .replace(loaded_params);
            Ok(())
        }
        // Error while generating/reading file/writing file
        Err(e) => Err(e),
    }
}

/// Generate `G2_UNIVERSAL_PARAMETERS` and store it in memory.
/// This function should be called exactly once during program execution and before any call to
/// `get_g2_committer_key()`. Further calls leave `G2_UNIVERSAL_PARAMETERS` unchanged and return an
/// error instead.
/// The parameter `max_degree` is required in order to derive a unique hash for the key itself.
pub fn load_g2_committer_key(max_degree: usize) -> Result<(), SerializationError> {
    {
        let pp_g2_guard = G2_UNIVERSAL_PARAMS.read().map_err(|_| {
            SerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to acquire lock for G2_UNIVERSAL_PARAMS".to_owned(),
            ))
        })?;
        if pp_g2_guard.is_some() {
            return Err(SerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "G2_UNIVERSAL_PARAMS has already been generated",
            )));
        }
    }
    log::info!("Generating G2 Dlog Keys of degree: {}", max_degree);
    match load_universal_params::<G2>(max_degree) {
        // Generation/Loading successful, assign the key to the lazy_static
        Ok(loaded_params) => {
            G2_UNIVERSAL_PARAMS
                .write()
                .as_mut()
                .map_err(|_| {
                    SerializationError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "G2_UNIVERSAL_PARAMS write failed",
                    ))
                })?
                .replace(loaded_params);
            Ok(())
        }
        // Error while generating/reading file/writing file
        Err(e) => Err(e),
    }
}

/// If `G1_UNIVERSAL_PARAMETERS` has been initialized, return `CommitterKeyG1`, otherwise return
/// Error.
/// If `supported_degree.is_some()`, then `CommitterKeyG1` is trimmed to the specified size.
pub fn get_g1_committer_key(
    supported_degree: Option<usize>,
) -> Result<CommitterKeyG1, ProvingSystemError> {
    let pp_g1_guard = G1_UNIVERSAL_PARAMS.read().map_err(|_| {
        ProvingSystemError::Other("Failed to acquire lock for G1_UNIVERSAL_PARAMS".to_owned())
    })?;

    if pp_g1_guard.is_some() {
        let supported_degree =
            supported_degree.unwrap_or_else(|| pp_g1_guard.as_ref().unwrap().max_degree());
        // TODO: Everytime the committer key is trimmed, a copy of the generators is performed.
        //   Currently the generators in the CommitterKey struct are stored as a Vec. Maybe we can
        //   do better by defining them as a slice with some lifetime?
        let (ck, _) =
            InnerProductArgPC::<_, Digest>::trim(&pp_g1_guard.as_ref().unwrap(), supported_degree)
                .map_err(|err| ProvingSystemError::Other(err.to_string()))?;
        Ok(ck)
    } else {
        Err(ProvingSystemError::CommitterKeyNotInitialized)
    }
}

/// If `G2_UNIVERSAL_PARAMETERS` has been initialized, return `CommitterKeyG2`, otherwise return
/// Error.
/// If `supported_degree.is_some()`, then `CommitterKeyG2` is trimmed to the specified size.
pub fn get_g2_committer_key(
    supported_degree: Option<usize>,
) -> Result<CommitterKeyG2, ProvingSystemError> {
    let pp_g2_guard = G2_UNIVERSAL_PARAMS.read().map_err(|_| {
        ProvingSystemError::Other("Failed to acquire lock for G2_UNIVERSAL_PARAMS".to_owned())
    })?;

    if pp_g2_guard.is_some() {
        let supported_degree =
            supported_degree.unwrap_or_else(|| pp_g2_guard.as_ref().unwrap().max_degree());
        // TODO: Everytime the committer key is trimmed, a copy of the generators is performed.
        //   Currently the generators in the CommitterKey struct are stored as a Vec. Maybe we can
        //   do better by defining them as a slice with some lifetime?
        let (ck, _) =
            InnerProductArgPC::<_, Digest>::trim(&pp_g2_guard.as_ref().unwrap(), supported_degree)
                .map_err(|err| ProvingSystemError::Other(err.to_string()))?;
        Ok(ck)
    } else {
        Err(ProvingSystemError::CommitterKeyNotInitialized)
    }
}

fn load_universal_params<G: AffineCurve>(
    max_degree: usize,
) -> Result<UniversalParams<G>, SerializationError> {
    let pp = InnerProductArgPC::<G, Digest>::setup(max_degree)
        .map_err(|_| SerializationError::InvalidData)?;

    log::debug!("Generated DLOG keys: {:?}", pp);
    // Return the read/generated universal parameters
    Ok(pp)
}

#[cfg(test)]
/// To ensure consistency across tests, each test should initialize the committer keys to the same
/// value of `max_degree`. For this reason the following constant is defined.
pub(crate) const COMMITTER_KEY_MAX_DEGREE_FOR_TESTING: usize = 1 << 10;

#[cfg(test)]
mod test {
    use super::*;

    use poly_commit::ipa_pc::InnerProductArgPC;
    use poly_commit::PolynomialCommitment;
    use serial_test::serial;

    #[test]
    #[serial]
    fn check_load_g1_committer_key() {
        let max_degree = COMMITTER_KEY_MAX_DEGREE_FOR_TESTING;
        let supported_degree = COMMITTER_KEY_MAX_DEGREE_FOR_TESTING / 2;

        let pp = InnerProductArgPC::<G1, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G1, Digest>::trim(&pp, supported_degree).unwrap();

        let _result_g1 = load_g1_committer_key(max_degree);

        let ck = get_g1_committer_key(Some(supported_degree));

        assert!(ck.is_ok());

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
        let max_degree = COMMITTER_KEY_MAX_DEGREE_FOR_TESTING;
        let supported_degree = COMMITTER_KEY_MAX_DEGREE_FOR_TESTING / 2;

        let pp = InnerProductArgPC::<G2, Digest>::setup(max_degree).unwrap();
        let (pk, _) = InnerProductArgPC::<G2, Digest>::trim(&pp, supported_degree).unwrap();

        let _result_g2 = load_g2_committer_key(max_degree);

        let ck = get_g2_committer_key(Some(supported_degree));

        assert!(ck.is_ok());

        let ck = ck.as_ref().unwrap();

        assert_eq!(pk.comm_key, ck.comm_key);
        assert_eq!(pk.h, ck.h);
        assert_eq!(pk.s, ck.s);
        assert_eq!(pk.max_degree, ck.max_degree);
        assert_eq!(pk.hash, ck.hash);
        assert_eq!(pp.hash, ck.hash);
    }
}
