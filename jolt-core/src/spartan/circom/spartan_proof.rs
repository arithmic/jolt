use ark_bn254::Bn254;
use ark_grumpkin::{Fr as Scalar, Fq as Fp, Projective};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_std::Zero;

use super::grand_product::convert_from_batched_GKRProof_to_circom_hyrax;
use super::hyrax::hyrax_eval_proof_to_circom;
use super::hyrax::HyraxEvalProofCircom;
use super::non_native::convert_vec_to_fqq;
use super::reduced_opening_proof::ReducedOpeningProofCircomHyrax;
use super::{

    memory_check::{ convert_multiset_hashes_to_circom, SparkMemoryCheckingProofCircom },
    non_native::{ convert_to_3_limbs, Fqq },
    reduced_opening_proof::{

        HyperKZGProofCircom,
        ReducedOpeningProofCircom,
    },
    sum_check::{ convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom },
};

use std::fmt;
use std::fs::File;

use crate::lasso::memory_checking::StructuredPolynomialData;
use crate::poly::commitment::hyperkzg::HyperKZG;
use crate::poly::commitment::hyrax::HyraxScheme;
use crate::spartan::spartan_memory_checking::SpartanPreprocessing;
use crate::utils::poseidon_transcript::GrumpkinPoseidonTranscript;
use crate::{
    field::JoltField,
    poly::commitment::commitment_scheme::CommitmentScheme,
    spartan::spartan_memory_checking::SpartanProof,
    utils::transcript::Transcript,
};

use super::spartan_memory_checking::SpartanOpenings;


pub struct SpartanProofHyraxCircom {
    pub outer_sumcheck_proof: SumcheckInstanceProofCircom,
    pub inner_sumcheck_proof: SumcheckInstanceProofCircom,
    // pub spark_sumcheck_proof: SumcheckInstanceProofCircom,
    pub outer_sumcheck_claims: [Fqq; 3],
    pub inner_sumcheck_claims: [Fqq; 4],
    // pub spark_sumcheck_claims: [Fqq; 9],
    // pub memory_checking: SparkMemoryCheckingProofCircom,
    pub joint_opening_proof: HyraxEvalProofCircom,
}

impl SpartanProofHyraxCircom {
    pub fn new(
        outer_sumcheck_proof: SumcheckInstanceProofCircom,
        inner_sumcheck_proof: SumcheckInstanceProofCircom,
        // spark_sumcheck_proof: SumcheckInstanceProofCircom,
        outer_sumcheck_claims: [Fqq; 3],
        inner_sumcheck_claims: [Fqq; 4],
        // spark_sumcheck_claims: [Fqq; 9],
        // memory_checking: SparkMemoryCheckingProofCircom,
        joint_opening_proof: HyraxEvalProofCircom
    ) -> Self {
        Self {
            outer_sumcheck_proof,
            inner_sumcheck_proof,
            // spark_sumcheck_proof,
            outer_sumcheck_claims,
            inner_sumcheck_claims,
            // spark_sumcheck_claims,
            // memory_checking,
            joint_opening_proof
        }
    }

    pub fn parse_spartan_proof(
        proof: &SpartanProof<Scalar, HyraxScheme<Projective, GrumpkinPoseidonTranscript<Fp>>, GrumpkinPoseidonTranscript<Fp>>
    ) -> Self {
        parse_spartan_proof_hyrax(proof)
    }
}

impl fmt::Debug for SpartanProofHyraxCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // "spark_sumcheck_claims": {:?},
        // "memory_checking": {:?},
        // "spark_sumcheck_proof": {:?},
        write!(
            f,
            r#"
            {{
            "outer_sumcheck_proof": {:?},
            "outer_sumcheck_claims": {:?},
            "inner_sumcheck_proof": {:?},
            "inner_sumcheck_claims": {:?},
            "joint_opening_proof": {:?}
            }}"#,
            self.outer_sumcheck_proof,
            self.outer_sumcheck_claims,
            self.inner_sumcheck_proof,
            self.inner_sumcheck_claims,
            // self.spark_sumcheck_proof,
            // self.spark_sumcheck_claims,
            // self.memory_checking,
            self.joint_opening_proof
        )
    }
}

pub fn parse_spartan_proof_hyrax(
    proof: &SpartanProof<Scalar, HyraxScheme<Projective, GrumpkinPoseidonTranscript<Fp>>, GrumpkinPoseidonTranscript<Fp>>
) -> SpartanProofHyraxCircom {
    let outer_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.outer_sumcheck_proof);
    let inner_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.inner_sumcheck_proof);
    // let spark_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.spark_sumcheck_proof);
    let outer_sumcheck_claims = [
        Fqq {
            element: proof.outer_sumcheck_claims.0,
            limbs: convert_to_3_limbs(proof.outer_sumcheck_claims.0),
        },
        Fqq {
            element: proof.outer_sumcheck_claims.1,
            limbs: convert_to_3_limbs(proof.outer_sumcheck_claims.1),
        },
        Fqq {
            element: proof.outer_sumcheck_claims.2,
            limbs: convert_to_3_limbs(proof.outer_sumcheck_claims.2),
        },
    ];
    let inner_sumcheck_claims = [
        Fqq {
            element: proof.inner_sumcheck_claims.0,
            limbs: convert_to_3_limbs(proof.inner_sumcheck_claims.0),
        },
        Fqq {
            element: proof.inner_sumcheck_claims.1,
            limbs: convert_to_3_limbs(proof.inner_sumcheck_claims.1),
        },
        Fqq {
            element: proof.inner_sumcheck_claims.2,
            limbs: convert_to_3_limbs(proof.inner_sumcheck_claims.2),
        },
        Fqq {
            element: proof.inner_sumcheck_claims.3,
            limbs: convert_to_3_limbs(proof.inner_sumcheck_claims.3),
        },
    ];



 
    SpartanProofHyraxCircom::new(
        outer_sumcheck_proof,
        inner_sumcheck_proof,
        outer_sumcheck_claims,
        inner_sumcheck_claims,
      
        hyrax_eval_proof_to_circom(
            &proof.pcs_proof
        )
    )
}

pub fn convert_and_flatten_spark_openings(openings: &SpartanOpenings<Scalar>) -> [Fqq; 24] {
    let mut flattened_opening = [
        Fqq {
            element: Scalar::zero(),
            limbs: [Fp::zero(); 3],
        };
        24
    ];

    let read_write_opening = openings.read_write_values();
    for i in 0..18 {
        flattened_opening[i] = Fqq {
            element: *read_write_opening[i],
            limbs: convert_to_3_limbs(*read_write_opening[i]),
        };
    }
    let init_final_opening = openings.init_final_values();

    for i in 0..6 {
        flattened_opening[18 + i] = Fqq {
            element: *init_final_opening[i],
            limbs: convert_to_3_limbs(*init_final_opening[i]),
        };
    }
    flattened_opening
}


pub fn preprocessing_to_pi_circom(preprocessing:&SpartanPreprocessing<Scalar>)->Vec<Fqq>{
    convert_vec_to_fqq(&preprocessing.inputs)
}