use bit_vec::BitVec;

use algebra::{
    fields::tweedle::Fr as TweedleFr, ToConstraintField//FromBits
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
    let bv = BitVec::from_bytes(&uncompressed_bit_vector);
    let bool_vector: Vec<bool> = bv.into_iter().map(|x| x).collect();

    let height = 12;
    let num_leaves = 1 << height;
    let mut mt = TweedlePoseidonMHT::init(
        height,
        num_leaves,
    );

    let leaves = bool_vector.to_field_elements()?;

    leaves[..].iter().for_each(|&leaf| { mt.append(leaf); });

    match mt.finalize_in_place().root() {
        Some(x) => Ok(x),
        None => Err("Unable to compute the merkle tree root hash")?
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn merkle_tree_trivial() {
        let mut bit_vector: Vec<u8> = vec![0; 63];

        assert!(merkle_root_from_bytes(&bit_vector, bit_vector.len()).is_err());

        bit_vector.clear();
        bit_vector.push(0);

        for i in 0..63 {
            bit_vector.push(i);
        }
        
        assert!(merkle_root_from_bytes(&bit_vector, bit_vector.len() - 1).is_ok());
    }
}