use core::fmt;
use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
use ark_ff::Field;
use crate::{r1cs::{inputs::JoltR1CSInputs, spartan::UniformSpartanProof}, utils::poseidon_transcript::PoseidonTranscript};
use crate::jolt::vm::rv32i_vm::{C, M};
use super::{helper_non_native::{convert_to_3_limbs, Fqq}, helper_sum_check::{convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom}};

// use crate::{helper_non_native::{convert_to_3_limbs, Fqq}, helper_sum_check::{convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom}};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct UniformSpartanProofCircom{
    pub outer_sumcheck_proof: SumcheckInstanceProofCircom,
    pub outer_sumcheck_claims: [Fqq; 3],
    pub inner_sumcheck_proof: SumcheckInstanceProofCircom,
    pub claimed_witness_evals: Vec<Fqq>
}

impl fmt::Debug for UniformSpartanProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "outer_sumcheck_proof": {:?},
            "outer_sumcheck_claims": {:?},
            "inner_sumcheck_proof": {:?},
            "claimed_witness_evals": {:?}
            }}"#,
            self.outer_sumcheck_proof, self.outer_sumcheck_claims, self.inner_sumcheck_proof, self.claimed_witness_evals,
        )
    }
}

pub fn compute_uniform_spartan_to_circom(uni_spartan_proof: UniformSpartanProof<C, JoltR1CSInputs, Scalar, PoseidonTranscript<Fp>>) -> UniformSpartanProofCircom {

    let mut outer_s_c_claims: [Fqq; 3] = [Fqq{
        element:Scalar::ZERO,
        limbs: convert_to_3_limbs(Scalar::ZERO)
    } ; 3];
    outer_s_c_claims[0] = Fqq{
        element: uni_spartan_proof.outer_sumcheck_claims.0,
        limbs: convert_to_3_limbs(uni_spartan_proof.outer_sumcheck_claims.0)
    };
    outer_s_c_claims[1] = Fqq{
        element: uni_spartan_proof.outer_sumcheck_claims.1,
        limbs: convert_to_3_limbs(uni_spartan_proof.outer_sumcheck_claims.1)
    };   
    outer_s_c_claims[2] = Fqq{
        element: uni_spartan_proof.outer_sumcheck_claims.2,
        limbs: convert_to_3_limbs(uni_spartan_proof.outer_sumcheck_claims.2)
    };



    let mut claimed_witness_evals = Vec::new();
    for i in 0..uni_spartan_proof.claimed_witness_evals.len(){
        claimed_witness_evals.push(
            Fqq{
                element: uni_spartan_proof.claimed_witness_evals[i],
                limbs: convert_to_3_limbs(uni_spartan_proof.claimed_witness_evals[i])
            }
        );
    }

    UniformSpartanProofCircom{
        outer_sumcheck_proof: convert_sum_check_proof_to_circom(&uni_spartan_proof.outer_sumcheck_proof),
        outer_sumcheck_claims: outer_s_c_claims,
        inner_sumcheck_proof: convert_sum_check_proof_to_circom(&uni_spartan_proof.inner_sumcheck_proof),
        claimed_witness_evals: claimed_witness_evals,
    }
}