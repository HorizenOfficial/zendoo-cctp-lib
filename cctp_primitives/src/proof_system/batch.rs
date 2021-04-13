use crate::{FieldElement, G1, G2, SerializationUtils, CoboundaryMarlin, Digest, Darlin};
use rand::RngCore;
use crate::proof_system::{
    ProvingSystemUtils, init::{G1_COMMITTER_KEY, G2_COMMITTER_KEY}
};
use algebra::SerializationError;
use proof_systems::darlin::pcd::{GeneralPCD, simple_marlin::SimpleMarlinPCD, final_darlin::FinalDarlinPCD};
use rayon::prelude::*;

pub fn batch_verify_proofs<R: RngCore>(
    coboundary_marlin_proofs_bytes: Vec<Vec<u8>>,
    coboundary_marlin_vks_bytes:    Vec<Vec<u8>>,
    coboundary_marlin_inputs:       Vec<Vec<FieldElement>>,
    final_darlin_proofs_bytes:      Vec<Vec<u8>>,
    final_darlin_vks_bytes:         Vec<Vec<u8>>,
    final_darlin_inputs:            Vec<Vec<FieldElement>>,
    rng:                            &mut R
) -> Result<bool, Option<usize>>
{
    // Deserialize and collect into PCDs the Coboundary Marlin related data
    let mut pcds_vks = coboundary_marlin_proofs_bytes.into_par_iter()
        .zip(coboundary_marlin_vks_bytes)
        .zip(coboundary_marlin_inputs)
        .map(|((proof_bytes, vk_bytes), inputs)|{
            let (proof, vk) = deserialize_data::<CoboundaryMarlin>(proof_bytes, vk_bytes)?;
            let pcd = GeneralPCD::SimpleMarlin(SimpleMarlinPCD::<G1, Digest>::new(proof, inputs));
            Ok((pcd, vk))
        }).collect::<Result<Vec<_>, SerializationError>>().map_err(|_| None)?;

    // Deserialize and collect into PCDs the (Final) Darlin related data
    pcds_vks.append(&mut final_darlin_proofs_bytes.into_par_iter()
        .zip(final_darlin_vks_bytes)
        .zip(final_darlin_inputs)
        .map(|((proof_bytes, vk_bytes), inputs)|{
            let (proof, vk) = deserialize_data::<Darlin>(proof_bytes, vk_bytes)?;
            let pcd = GeneralPCD::FinalDarlin(FinalDarlinPCD::<G1, G2, Digest>::new(proof, inputs));
            Ok((pcd, vk))
        }).collect::<Result<Vec<_>, SerializationError>>().map_err(|_| None)?
    );

    //Perform the batch verification
    let pcds = pcds_vks.iter().map(|(pcd, _)| pcd.clone()).collect::<Vec<_>>();
    let vks = pcds_vks.into_iter().map(|(_, vk)| vk).collect::<Vec<_>>();

    let g1_ck = G1_COMMITTER_KEY.lock().unwrap();
    let g2_ck = G2_COMMITTER_KEY.lock().unwrap();

    let result = proof_systems::darlin::proof_aggregator::batch_verify_proofs(
        pcds.as_slice(), vks.as_slice(), &g1_ck, &g2_ck, rng
    )?;

    Ok(result)
}

fn deserialize_data<P: ProvingSystemUtils<FieldElement>>(
    proof_bytes: Vec<u8>,
    vk_bytes:   Vec<u8>
) -> Result<(P::Proof, P::VerifierKey), SerializationError>
{
    let proof = <P::Proof as SerializationUtils>::from_byte_vec(proof_bytes)?;
    let vk = <P::VerifierKey as SerializationUtils>::from_byte_vec(vk_bytes)?;

    Ok((proof, vk))
}