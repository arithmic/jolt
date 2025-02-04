use core::fmt;

use super::{struct_fq::FqCircom, sum_check_gkr::{convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom}};
use crate::{poly::{commitment::hyperkzg::HyperKZG, opening_proof::ReducedOpeningProof}, utils::poseidon_transcript::PoseidonTranscript};
use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReducedOpeningProofCircom{
    pub sumcheck_proof: SumcheckInstanceProofCircom,
    pub sumcheck_claims: Vec<FqCircom>,
    // pub joint_opening_proof: HyperKZGProofCircom
}

impl fmt::Debug for ReducedOpeningProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            // "joint_opening_proof": {:?}
            f,
            r#"{{
            "sumcheck_proof": {:?},
            "sumcheck_claims": {:?}
            }}"#,
            self.sumcheck_proof, self.sumcheck_claims
            // , self.joint_opening_proof
        )
    }
}

pub fn convert_reduced_opening_proof_to_circom(red_opening: ReducedOpeningProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>) -> ReducedOpeningProofCircom{
    let mut claims = Vec::new();
    // println!("red_opening.sumcheck_claims.len() is {}", red_opening.sumcheck_claims.len());
    for i in 0..red_opening.sumcheck_claims.len(){
        claims.push(
            FqCircom(red_opening.sumcheck_claims[i])
        )
    }
    ReducedOpeningProofCircom{
        sumcheck_proof: convert_sum_check_proof_to_circom(&red_opening.sumcheck_proof),
        sumcheck_claims: claims,
        // joint_opening_proof: hyper_kzg_proof_to_hyper_kzg_circom(red_opening.joint_opening_proof),
    }
}