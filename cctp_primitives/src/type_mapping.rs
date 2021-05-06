use algebra::{fields::tweedle::*, curves::tweedle::*, biginteger::BigInteger256, PrimeField, FpParameters};
use primitives::{
    crh::*,
    merkle_tree::*,
};
pub use primitives::merkle_tree::tweedle_dee::TWEEDLE_DEE_MHT_POSEIDON_PARAMETERS as GINGER_MHT_POSEIDON_PARAMETERS;
use proof_systems::darlin::{
    *, data_structures::*, pcd::simple_marlin::MarlinProof
};
use poly_commit::ipa_pc::*;
use blake2::Blake2s;

// Basic algebraic types

pub type FieldElement = Fr;
pub type G1 = dee::Affine;
pub type G2 = dum::Affine;
pub type G2Projective = dum::Projective;

pub type FieldBigInteger = BigInteger256;
pub type ScalarFieldElement = Fq;

//Field size in bytes
pub const FIELD_CAPACITY: usize = <Fr as PrimeField>::Params::CAPACITY as usize;
pub const FIELD_SIZE: usize = ((
    <Fr as PrimeField>::Params::MODULUS_BITS +
        <Fr as PrimeField>::Params::REPR_SHAVE_BITS
)/8) as usize;
pub const SCALAR_FIELD_SIZE: usize = ((
    <Fq as PrimeField>::Params::MODULUS_BITS +
        <Fq as PrimeField>::Params::REPR_SHAVE_BITS
)/8) as usize;
pub const GROUP_SIZE: usize = 2 * FIELD_SIZE + 1;
pub const GROUP_COMPRESSED_SIZE: usize = FIELD_SIZE + 1;

pub const MC_PK_SIZE: usize = 20;

// Crypto primitives instantiations
pub type FieldHash = TweedleFrPoseidonHash;
pub type BatchFieldHash = TweedleFrBatchPoseidonHash;

#[derive(Clone, Debug)]
pub struct GingerMHTParams;

impl FieldBasedMerkleTreeParameters for GingerMHTParams {
    type Data = FieldElement;
    type H = FieldHash;
    const MERKLE_ARITY: usize = 2;
    const ZERO_NODE_CST: Option<FieldBasedMerkleTreePrecomputedZeroConstants<'static, Self::H>> =
        Some(GINGER_MHT_POSEIDON_PARAMETERS);
}

impl BatchFieldBasedMerkleTreeParameters for GingerMHTParams {
    type BH = BatchFieldHash;
}

pub type GingerMHT = FieldBasedOptimizedMHT<GingerMHTParams>;
pub type GingerMHTPath = FieldBasedMHTPath<GingerMHTParams>;

// Polynomial Commitment instantiations
pub type Digest = Blake2s;
pub type IPAPC = InnerProductArgPC<G1, Digest>;
pub type CommitterKeyG1 = CommitterKey<G1>;
pub type CommitterKeyG2 = CommitterKey<G2>;

#[derive(Copy, Clone)]
#[repr(C)]
pub enum ProvingSystem {
    Undefined,
    Darlin,
    CoboundaryMarlin,
}

// Coboundary Marlin instantiations
pub type CoboundaryMarlin = marlin::Marlin<FieldElement, IPAPC, Digest>;
pub type CoboundaryMarlinProof = MarlinProof<G1, Digest>;
pub type CoboundaryMarlinProverKey = marlin::ProverKey<FieldElement, IPAPC>;
pub type CoboundaryMarlinVerifierKey = marlin::VerifierKey<FieldElement, IPAPC>;

// (Final) Darlin instantiations
pub type Darlin<'a> = FinalDarlin<'a, G1, G2, Digest>;
pub type DarlinProof = FinalDarlinProof<G1, G2, Digest>;
pub type DarlinProverKey = FinalDarlinProverKey<FieldElement, IPAPC>;
pub type DarlinVerifierKey = FinalDarlinVerifierKey<FieldElement, IPAPC>;

// Others
pub type Error = Box<dyn std::error::Error>;