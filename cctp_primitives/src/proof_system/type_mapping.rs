use algebra::curves::tweedle::dee::Affine;
use blake2::Blake2s;
use poly_commit::ipa_pc::InnerProductArgPC;

pub type IPAPC = InnerProductArgPC<Affine, Blake2s>;

