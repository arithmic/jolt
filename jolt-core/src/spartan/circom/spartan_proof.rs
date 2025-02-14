use ark_bn254::Bn254;
use ark_bn254::Fq as Fp;
use ark_bn254::Fr as Scalar;
use ark_bn254::G1Projective;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_std::Zero;

use super::grand_product::convert_from_batched_GKRProof_to_circom_hyrax;
use super::hyrax::hyrax_eval_proof_to_circom;
use super::non_native::convert_vec_to_fqq;
use super::reduced_opening_proof::ReducedOpeningProofCircomHyrax;
use super::{
    grand_product::convert_from_batched_GKRProof_to_circom,
    memory_check::{ convert_multiset_hashes_to_circom, SparkMemoryCheckingProofCircom },
    non_native::{ convert_to_3_limbs, Fqq },
    reduced_opening_proof::{
        hyper_kzg_proof_to_hyper_kzg_circom,
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
use crate::utils::poseidon_transcript::PoseidonTranscript;
use crate::{
    field::JoltField,
    poly::commitment::commitment_scheme::CommitmentScheme,
    spartan::spartan_memory_checking::SpartanProof,
    utils::transcript::Transcript,
};

use super::spartan_memory_checking::SpartanOpenings;

pub struct SpartanProofCircom {
    pub outer_sumcheck_proof: SumcheckInstanceProofCircom,
    pub inner_sumcheck_proof: SumcheckInstanceProofCircom,
    pub spark_sumcheck_proof: SumcheckInstanceProofCircom,
    pub outer_sumcheck_claims: [Fqq; 3],
    pub inner_sumcheck_claims: [Fqq; 4],
    pub spark_sumcheck_claims: [Fqq; 9],
    pub memory_checking: SparkMemoryCheckingProofCircom,
    pub opening_proof: ReducedOpeningProofCircom,
}

impl SpartanProofCircom {
    pub fn new(
        outer_sumcheck_proof: SumcheckInstanceProofCircom,
        inner_sumcheck_proof: SumcheckInstanceProofCircom,
        spark_sumcheck_proof: SumcheckInstanceProofCircom,
        outer_sumcheck_claims: [Fqq; 3],
        inner_sumcheck_claims: [Fqq; 4],
        spark_sumcheck_claims: [Fqq; 9],
        memory_checking: SparkMemoryCheckingProofCircom,
        opening_proof: ReducedOpeningProofCircom
    ) -> Self {
        Self {
            outer_sumcheck_proof,
            inner_sumcheck_proof,
            spark_sumcheck_proof,
            outer_sumcheck_claims,
            inner_sumcheck_claims,
            spark_sumcheck_claims,
            memory_checking,
            opening_proof,
        }
    }

    pub fn parse_spartan_proof(
        proof: &SpartanProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>
    ) -> Self {
        parse_spartan_proof(proof)
    }
}

impl fmt::Debug for SpartanProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
            {{
            "outer_sumcheck_proof": {:?},
            "outer_sumcheck_claims": {:?},
            "inner_sumcheck_proof": {:?},
            "inner_sumcheck_claims": {:?},
            "spark_sumcheck_proof": {:?},
            "spark_sumcheck_claims": {:?},
            "memory_checking": {:?},
            "opening_proof": {:?}
            }}"#,
            self.outer_sumcheck_proof,
            self.outer_sumcheck_claims,
            self.inner_sumcheck_proof,
            self.inner_sumcheck_claims,
            self.spark_sumcheck_proof,
            self.spark_sumcheck_claims,
            self.memory_checking,
            self.opening_proof
        )
    }
}

pub fn parse_spartan_proof(
    proof: &SpartanProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>
) -> SpartanProofCircom {
    let outer_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.outer_sumcheck_proof);
    let inner_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.inner_sumcheck_proof);
    let spark_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.spark_sumcheck_proof);
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

    let spark_sumcheck_claims = [
        Fqq {
            element: proof.spark_sumcheck_claims[0],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[0]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[1],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[1]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[2],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[2]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[3],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[3]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[4],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[4]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[5],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[5]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[6],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[6]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[7],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[7]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[8],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[8]),
        },
    ];

    let memory_checking = SparkMemoryCheckingProofCircom {
        multiset_hashes: convert_multiset_hashes_to_circom(&proof.memory_checking.multiset_hashes),
        read_write_grand_product: convert_from_batched_GKRProof_to_circom(
            &proof.memory_checking.read_write_grand_product
        ),
        init_final_grand_product: convert_from_batched_GKRProof_to_circom(
            &proof.memory_checking.init_final_grand_product
        ),
        openings: convert_and_flatten_spark_openings(&proof.memory_checking.openings).to_vec(),
    };

    let opening_proof = ReducedOpeningProofCircom {
        sumcheck_proof: convert_sum_check_proof_to_circom(&proof.opening_proof.sumcheck_proof),
        sumcheck_claims: proof.opening_proof.sumcheck_claims
            .iter()
            .map(|elem| Fqq {
                element: *elem,
                limbs: convert_to_3_limbs(*elem),
            })
            .collect(),
        joint_opening_proof: hyper_kzg_proof_to_hyper_kzg_circom(
            &proof.opening_proof.joint_opening_proof
        ),
    };

    SpartanProofCircom::new(
        outer_sumcheck_proof,
        inner_sumcheck_proof,
        spark_sumcheck_proof,
        outer_sumcheck_claims,
        inner_sumcheck_claims,
        spark_sumcheck_claims,
        memory_checking,
        opening_proof
    )
}



pub struct SpartanProofHyraxCircom {
    pub outer_sumcheck_proof: SumcheckInstanceProofCircom,
    pub inner_sumcheck_proof: SumcheckInstanceProofCircom,
    pub spark_sumcheck_proof: SumcheckInstanceProofCircom,
    pub outer_sumcheck_claims: [Fqq; 3],
    pub inner_sumcheck_claims: [Fqq; 4],
    pub spark_sumcheck_claims: [Fqq; 9],
    pub memory_checking: SparkMemoryCheckingProofCircom,
    pub opening_proof: ReducedOpeningProofCircomHyrax,
}

impl SpartanProofHyraxCircom {
    pub fn new(
        outer_sumcheck_proof: SumcheckInstanceProofCircom,
        inner_sumcheck_proof: SumcheckInstanceProofCircom,
        spark_sumcheck_proof: SumcheckInstanceProofCircom,
        outer_sumcheck_claims: [Fqq; 3],
        inner_sumcheck_claims: [Fqq; 4],
        spark_sumcheck_claims: [Fqq; 9],
        memory_checking: SparkMemoryCheckingProofCircom,
        opening_proof: ReducedOpeningProofCircomHyrax
    ) -> Self {
        Self {
            outer_sumcheck_proof,
            inner_sumcheck_proof,
            spark_sumcheck_proof,
            outer_sumcheck_claims,
            inner_sumcheck_claims,
            spark_sumcheck_claims,
            memory_checking,
            opening_proof,
        }
    }

    pub fn parse_spartan_proof(
        proof: &SpartanProof<Scalar, HyraxScheme<G1Projective, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>
    ) -> Self {
        parse_spartan_proof_hyrax(proof)
    }
}

impl fmt::Debug for SpartanProofHyraxCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
            {{
            "outer_sumcheck_proof": {:?},
            "outer_sumcheck_claims": {:?},
            "inner_sumcheck_proof": {:?},
            "inner_sumcheck_claims": {:?},
            "spark_sumcheck_proof": {:?},
            "spark_sumcheck_claims": {:?},
            "memory_checking": {:?},
            "opening_proof": {:?}
            }}"#,
            self.outer_sumcheck_proof,
            self.outer_sumcheck_claims,
            self.inner_sumcheck_proof,
            self.inner_sumcheck_claims,
            self.spark_sumcheck_proof,
            self.spark_sumcheck_claims,
            self.memory_checking,
            self.opening_proof
        )
    }
}

pub fn parse_spartan_proof_hyrax(
    proof: &SpartanProof<Scalar, HyraxScheme<G1Projective, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>
) -> SpartanProofHyraxCircom {
    let outer_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.outer_sumcheck_proof);
    let inner_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.inner_sumcheck_proof);
    let spark_sumcheck_proof = convert_sum_check_proof_to_circom(&proof.spark_sumcheck_proof);
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

    let spark_sumcheck_claims = [
        Fqq {
            element: proof.spark_sumcheck_claims[0],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[0]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[1],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[1]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[2],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[2]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[3],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[3]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[4],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[4]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[5],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[5]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[6],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[6]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[7],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[7]),
        },
        Fqq {
            element: proof.spark_sumcheck_claims[8],
            limbs: convert_to_3_limbs(proof.spark_sumcheck_claims[8]),
        },
    ];

    let memory_checking = SparkMemoryCheckingProofCircom {
        multiset_hashes: convert_multiset_hashes_to_circom(&proof.memory_checking.multiset_hashes),
        read_write_grand_product: convert_from_batched_GKRProof_to_circom_hyrax(
            &proof.memory_checking.read_write_grand_product
        ),
        init_final_grand_product: convert_from_batched_GKRProof_to_circom_hyrax(
            &proof.memory_checking.init_final_grand_product
        ),
        openings: convert_and_flatten_spark_openings(&proof.memory_checking.openings).to_vec(),
    };

    let opening_proof = ReducedOpeningProofCircomHyrax {
        sumcheck_proof: convert_sum_check_proof_to_circom(&proof.opening_proof.sumcheck_proof),
        sumcheck_claims: proof.opening_proof.sumcheck_claims
            .iter()
            .map(|elem| Fqq {
                element: *elem,
                limbs: convert_to_3_limbs(*elem),
            })
            .collect(),
        joint_opening_proof: hyrax_eval_proof_to_circom(
            &proof.opening_proof.joint_opening_proof
        ),
    };

    SpartanProofHyraxCircom::new(
        outer_sumcheck_proof,
        inner_sumcheck_proof,
        spark_sumcheck_proof,
        outer_sumcheck_claims,
        inner_sumcheck_claims,
        spark_sumcheck_claims,
        memory_checking,
        opening_proof
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