use {
    algebra::curves::tweedle::{
        dum::{
            Affine as DumAffine, Projective as DumProjective, TweedledumParameters,
        },
        dee::{
            Affine as DeeAffine, Projective as DeeProjective,
        },
    },
    primitives::crh::poseidon::parameters::tweedle_dee::{
        TweedleFrBatchPoseidonHash, TweedleFrPoseidonHash,
    },
};
pub use primitives::merkle_tree::tweedle_dee::TWEEDLE_DEE_MHT_POSEIDON_PARAMETERS as GINGER_MHT_POSEIDON_PARAMETERS;

use algebra::{AffineCurve, Field, FpParameters, ModelParameters, PrimeField, ProjectiveCurve};
use lazy_static::lazy_static;
use primitives::{
    crh::{
        bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters},
        pedersen::PedersenWindow,
    },
    merkle_tree::*,
    signature::schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme,
    },
    vrf::ecvrf::{FieldBasedEcVrf, FieldBasedEcVrfProof},
};
use blake2::Blake2s;
use poly_commit::ipa_pc::*;
pub use proof_systems::darlin::pcd::simple_marlin::MarlinProof;
use proof_systems::darlin::{data_structures::*, *};

use type_mappings::*;
pub type Error = Box<dyn std::error::Error>;

generate_all_types_and_functions!(
    DumAffine,
    DumProjective,
    TweedledumParameters,
    TweedleFrPoseidonHash,
    TweedleFrBatchPoseidonHash,
    GINGER_MHT_POSEIDON_PARAMETERS,
    2
);

// Basic algebraic types
pub type DualGroup = DeeAffine;
pub type DualGroupProjective = DeeProjective;

pub const MC_PK_SIZE: usize = 20;

// Polynomial Commitment instantiations
pub type Digest = Blake2s;
pub type IPAPC = InnerProductArgPC<DualGroup, Digest>;
pub type CommitterKeyDualGroup = CommitterKey<DualGroup>;
pub type CommitterKeyGroup = CommitterKey<Group>;

// Coboundary Marlin instantiations
pub type CoboundaryMarlin = marlin::Marlin<FieldElement, IPAPC, Digest>;
pub type CoboundaryMarlinProof = MarlinProof<DualGroup, Digest>;
pub type CoboundaryMarlinProverKey = marlin::ProverKey<FieldElement, IPAPC>;
pub type CoboundaryMarlinVerifierKey = marlin::VerifierKey<FieldElement, IPAPC>;

// (Final) Darlin instantiations
pub type Darlin<'a> = FinalDarlin<'a, DualGroup, Group, Digest>;
pub type DarlinProof = FinalDarlinProof<DualGroup, Group, Digest>;
pub type DarlinProverKey = FinalDarlinProverKey<FieldElement, IPAPC>;
pub type DarlinVerifierKey = FinalDarlinVerifierKey<FieldElement, IPAPC>;