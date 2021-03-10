use bitvec::prelude::*;

use algebra::{
    fields::tweedle::Fr as TweedleFr, ToConstraintField
};

use primitives::{
    crh::poseidon::parameters::tweedle::{TweedleFrPoseidonHash, TweedleFrBatchPoseidonHash},
    merkle_tree::field_based_mht::{
        FieldBasedMerkleTreeParameters, FieldBasedMerkleTreePrecomputedEmptyConstants,
        BatchFieldBasedMerkleTreeParameters, FieldBasedOptimizedMHT, FieldBasedMerkleTree,
        parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS
    }
};

use super::compression;

#[derive(Clone, Debug)]
struct TweedleFieldBasedMerkleTreeParams;
impl FieldBasedMerkleTreeParameters for TweedleFieldBasedMerkleTreeParams {
    type Data = TweedleFr;
    type H = TweedleFrPoseidonHash;
    const MERKLE_ARITY: usize = 2;
    const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> = Some(TWEEDLE_MHT_POSEIDON_PARAMETERS);
}

impl BatchFieldBasedMerkleTreeParameters for TweedleFieldBasedMerkleTreeParams {
    type BH = TweedleFrBatchPoseidonHash;
}

type TweedlePoseidonMHT = FieldBasedOptimizedMHT<TweedleFieldBasedMerkleTreeParams>;

type Error = Box<dyn std::error::Error>;

pub fn merkle_root_from_bytes(compressed_bit_vector: &[u8], expected_uncompressed_size: usize) -> Result<algebra::Fp256<algebra::fields::tweedle::FrParameters>, Error> {

    let uncompressed_bit_vector = compression::decompress_bit_vector(compressed_bit_vector, expected_uncompressed_size)?;
    let bv = BitVec::<Lsb0, _>::from_slice(&uncompressed_bit_vector)?.into_vec();

    let height = 12;
    let num_leaves = 1 << height;
    let mut mt = TweedlePoseidonMHT::init(
        height,
        num_leaves,
    );

    let leaves = bv.to_field_elements()?;
    
    leaves[..].iter().for_each(|&leaf| { mt.append(leaf); });
    mt.finalize_in_place().root().ok_or(Err("Unable to compute the merkle tree root hash")?)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn merkle_tree_trivial() {
        let bit_vector = vec![0u8; 5];

        assert!(merkle_root_from_bytes(&bit_vector, bit_vector.len() - 1).is_err());
    }
}