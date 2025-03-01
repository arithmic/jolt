use super::*;
use crate::parse::jolt::to_limbs;
use crate::poly::commitment::commitment_scheme::CommitmentScheme;
use crate::poly::unipoly::UniPoly;
use crate::spartan::spartan_memory_checking::{R1CSConstructor, SpartanProof};
use crate::subprotocols::sumcheck::SumcheckInstanceProof;
use crate::utils::thread::drop_in_background_thread;
use crate::{poly::commitment::hyrax::HyraxScheme, utils::poseidon_transcript::PoseidonTranscript};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, Field, PrimeField};
use itertools::Itertools;
use serde_json::json;

type Fr = ark_grumpkin::Fr;
type Fq = ark_grumpkin::Fq;
type ProofTranscript = PoseidonTranscript<Fr, ark_grumpkin::Fq>;
type Pcs = HyraxScheme<ark_grumpkin::Projective, ProofTranscript>;

pub fn from_limbs<F: PrimeField, K: PrimeField>(limbs: Vec<F>) -> K {
    assert_eq!(limbs.len(), 3);
    let bits = limbs[0]
        .into_bigint()
        .to_bits_le()
        .iter()
        .take(125)
        .chain(limbs[1].into_bigint().to_bits_le().iter().take(125))
        .chain(limbs[2].into_bigint().to_bits_le().iter().take(4))
        .cloned()
        .collect_vec();
    K::from_le_bytes_mod_order(&BigInt::<4>::from_bits_le(&bits).to_bytes_le())
}

impl Parse for Fr {
    fn format(&self) -> serde_json::Value {
        let limbs = to_limbs::<Fr, Fq>(*self);
        json!({
            "limbs": [limbs[0].to_string(), limbs[1].to_string(), limbs[2].to_string()]
        })
    }
}

struct PostponedEval {
    pub point: Vec<Fq>,
    pub eval: Fq,
}

impl PostponedEval {
    pub fn new(witness: Vec<Fr>, postponed_eval_size: usize) -> Self {
        let point = (0..postponed_eval_size)
            .map(|i| from_limbs::<Fr, Fq>(witness[2 + 3 * i..2 + 3 * i + 3].to_vec()))
            .collect();
        let eval = from_limbs::<Fr, Fq>(
            witness[2 + 3 * postponed_eval_size..2 + 3 * postponed_eval_size + 3].to_vec(),
        );

        Self { point, eval }
    }
}
impl Parse for PostponedEval {
    fn format(&self) -> serde_json::Value {
        let point: Vec<serde_json::Value> = self
            .point
            .iter()
            .map(|elem| elem.format_non_native())
            .collect();
        json!({
            "point": point,
            "eval": self.eval.format_non_native()
        })
    }
}

impl Parse for SpartanProof<Fr, Pcs, ProofTranscript> {
    fn format(&self) -> serde_json::Value {
        json!({
            "outer_sumcheck_proof": self.outer_sumcheck_proof.format(),
            "inner_sumcheck_proof": self.inner_sumcheck_proof.format(),
            "outer_sumcheck_claims": [self.outer_sumcheck_claims.0.format(),self.outer_sumcheck_claims.1.format(),self.outer_sumcheck_claims.2.format()],
            "inner_sumcheck_claims": [self.inner_sumcheck_claims.0.format(),self.inner_sumcheck_claims.1.format(),self.inner_sumcheck_claims.2.format(),self.inner_sumcheck_claims.3.format()],
            "pub_io_eval": self.pi_eval.format(),
            "joint_opening_proof": self.pcs_proof.format()
        })
    }
}

impl Parse for SumcheckInstanceProof<Fr, ProofTranscript> {
    fn format(&self) -> serde_json::Value {
        let uni_polys: Vec<serde_json::Value> =
            self.uni_polys.iter().map(|poly| poly.format()).collect();
        json!({
            "uni_polys": uni_polys,
        })
    }
}

impl Parse for UniPoly<Fr> {
    fn format(&self) -> serde_json::Value {
        let coeffs: Vec<serde_json::Value> =
            self.coeffs.iter().map(|coeff| coeff.format()).collect();
        json!({
            "coeffs": coeffs,
        })
    }
}
pub(crate) fn spartan_hyrax(
    linking_stuff: serde_json::Value,
    jolt_pi: serde_json::Value,
    spartan_1_digest: serde_json::Value,
    vk_spartan_1: serde_json::Value,
    vk_jolt_2: serde_json::Value,
    pub_io_len: usize,
    postponed_point_len: usize,
    file_paths: &Vec<PathBuf>,
    packages: &[&str],
    output_dir: &str,
) {
    let circom_template = "VerifySpartan";
    let prime = "bn128";

    let witness_file_path = format!("{}/{}_witness.json", output_dir, packages[1]).to_string();

    let z = read_witness::<Fr>(&witness_file_path);

    let constraint_path = format!("{}/{}_constraints.json", output_dir, packages[1]).to_string();

    let preprocessing =
        R1CSConstructor::<Fr>::construct(Some(&constraint_path), Some(&z), pub_io_len - 1);

    let commitment_shapes =
        SpartanProof::<Fr, Pcs, ProofTranscript>::commitment_shapes(preprocessing.vars.len());

    let pcs_setup = Pcs::setup(&commitment_shapes);
    let proof: SpartanProof<Fr, Pcs, ProofTranscript> =
        SpartanProof::<Fr, Pcs, ProofTranscript>::prove(&pcs_setup, &preprocessing);

    SpartanProof::<Fr, Pcs, ProofTranscript>::verify(&pcs_setup, &preprocessing, &proof).unwrap();

    let to_eval = PostponedEval::new(z, postponed_point_len);

    let spartan_hyrax_input = json!({
        "pub_io": {
                "jolt_pi": jolt_pi,
                "counter_jolt_1": 1.to_string(),
                "linking_stuff": linking_stuff,
                "vk_spartan_1": vk_spartan_1,
                "digest": spartan_1_digest,
                "vk_jolt_2": vk_jolt_2,
            },
        "counter_combined_r1cs": 2.to_string(),
        "to_eval": to_eval.format(),
        "setup": pcs_setup.format(),
        "digest": preprocessing.inst.get_digest().format(),
        "proof": proof.format(),
        "w_commitment": proof.witness_commit.format(),
    });

    write_json(&spartan_hyrax_input, output_dir, packages[2]);
    drop_in_background_thread(spartan_hyrax_input);
    drop_in_background_thread(preprocessing);

    let inner_num_rounds = proof.inner_sumcheck_proof.uni_polys.len();

    let spartan_hyrax_args = [
        proof.outer_sumcheck_proof.uni_polys.len(),
        inner_num_rounds,
        proof.inner_sumcheck_proof.uni_polys.len() - 1,
        postponed_point_len,
    ]
    .to_vec();

    drop_in_background_thread(proof);

    // Add component main to Circom file
    let public_inputs = ["counter_combined_r1cs", "to_eval", "pub_io", "digest"]
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    generate_circuit_and_witness(
        &file_paths[2],
        output_dir,
        circom_template,
        spartan_hyrax_args,
        prime,
        Some(public_inputs),
    );

    let witness_file_path = format!("{}/{}_witness.json", output_dir, packages[2]).to_string();

    let z = read_witness::<Fq>(&witness_file_path);

    let constraint_path = format!("{}/{}_constraints.json", output_dir, packages[2]).to_string();

    let _ = R1CSConstructor::<Fq>::construct(Some(&constraint_path), Some(&z), 20);

    let z = read_witness::<Fr>(&witness_file_path);
    let pub_io = z[0..1 + 1 + 3 * inner_num_rounds + pub_io_len - 1 + 40].to_vec();
    verify_postponed_eval(pub_io, inner_num_rounds);
}

// #[test]
// fn test_final_eval() {
//     use std::env;
//     let binding = env::current_dir().unwrap().join("src/parse/requirements");
//     let output_dir = binding.to_str().unwrap();
//     let witness_file_path = format!("{}/{}_witness.json", output_dir, "spartan_hyrax").to_string();

//     let z = read_witness::<Fr>(&witness_file_path);
//     let pub_io = z[0..1 + 1 + 3 * 24 + 1718 - 1 + 40].to_vec();

//     verify_postponed_eval(pub_io, 24);
// }

pub(crate) fn verify_postponed_eval(z: Vec<Fr>, l: usize) {
    let postponed_eval = &z[2..3 * l + 2];
    let vec_to_eval = &z[3 * l + 2..];

    let compressed_postponed_eval: Vec<Fr> = postponed_eval
        .chunks(3)
        .map(|chunk| from_limbs::<Fr, Fr>([chunk[0], chunk[1], chunk[2]].to_vec()))
        .collect::<Vec<Fr>>();
    let (pt, eval) = (
        compressed_postponed_eval[..compressed_postponed_eval.len() - 1].to_vec(),
        compressed_postponed_eval[compressed_postponed_eval.len() - 1],
    );

    let (vec_to_eval1, vec_to_eval2) = (
        vec_to_eval[..vec_to_eval.len() - 60].to_vec(),
        vec_to_eval[vec_to_eval.len() - 60..].to_vec(),
    );

    let comms: Vec<Fr> = vec_to_eval2
        .chunks(3)
        .map(|chunk| from_limbs::<Fr, Fr>([chunk[0], chunk[1], chunk[2]].to_vec()))
        .collect();

    let mut pub_io = [[Fr::ONE].to_vec(), vec_to_eval1, comms].concat();

    let pad_length = pub_io.len().next_power_of_two();
    let log_pad_length = pad_length.ilog2() as usize;

    pub_io.resize(pad_length, Fr::ZERO);

    let required_pt = pt[pt.len() - log_pad_length..].to_vec();
    let evals = evals(required_pt);

    let mut computed_eval = inner_product(pub_io, evals);
    computed_eval *= pt[0..pt.len() - log_pad_length]
        .iter()
        .map(|r| Fr::ONE - r)
        .product::<Fr>();

    assert_eq!(eval, computed_eval);
}

fn evals(r: Vec<Fr>) -> Vec<Fr> {
    let ell = r.len();
    let pow_2 = 1 << ell;

    let mut evals: Vec<Fr> = vec![Fr::from(1); pow_2];
    let mut size = 1;
    for j in 0..ell {
        // in each iteration, we double the size of chis
        size *= 2;
        for i in (0..size).rev().step_by(2) {
            // copy each element from the prior iteration twice
            let scalar = evals[i / 2];
            evals[i] = scalar * r[j];
            evals[i - 1] = scalar - evals[i];
        }
    }
    evals
}

fn inner_product(a: Vec<Fr>, b: Vec<Fr>) -> Fr {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.19;

// contract PostponedEval {
//     uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

//     function combineLimbs(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
//         return a + (b << 125) + (c << 250);
//     }

//     function verifyPostponedEval(uint256[] memory input, uint256 l) public pure {
//         uint256[] memory postponedEval = new uint256[](3 * l);
//         uint256[] memory vecToEval = new uint256[](input.length - 3 * l - 2);

//         unchecked {
//             for (uint i = 0; i < 3 * l; i++) {
//                 postponedEval[i] = input[i + 2];
//             }
//             for (uint i = 0; i < vecToEval.length; i++) {
//                 vecToEval[i] = input[3 * l + 2 + i];
//             }
//         }

//         uint256[] memory compressedPostponedEval = new uint256[](l);
//         unchecked {
//             for (uint i = 0; i < l; i++) {
//                 compressedPostponedEval[i] = combineLimbs(postponedEval[3 * i], postponedEval[3 * i + 1], postponedEval[3 * i + 2]);
//             }
//         }

//         uint256 eval = compressedPostponedEval[l - 1];
//         uint256[] memory pt = new uint256[](l - 1);
//         unchecked {
//             for (uint i = 0; i < l - 1; i++) {
//                 pt[i] = compressedPostponedEval[i];
//             }
//         }

//         uint256[] memory vecToEval1 = new uint256[](vecToEval.length - 60);
//         uint256[] memory vecToEval2 = new uint256[](60);

//         unchecked {
//             for (uint i = 0; i < vecToEval1.length ; i++) {
//                 vecToEval1[i] = vecToEval[i];
//             }
//             for (uint i = 0; i < 60; i++) {
//                 vecToEval2[i] = vecToEval[vecToEval.length - 60 + i];
//             }
//         }

//         uint256[] memory comms = new uint256[](vecToEval2.length / 3);
//         unchecked {
//             for (uint i = 0; i < 20; i++) {
//                 comms[i] = combineLimbs(vecToEval2[3 * i], vecToEval2[3 * i + 1], vecToEval2[3 * i + 2]);
//             }
//         }

//         uint256 pubIoLen = 1 + vecToEval1.length + comms.length;
//         uint256[] memory pubIo = new uint256[](pubIoLen);

//          pubIo[0] = 1;
//         unchecked {
//             for (uint i = 0; i < vecToEval1.length; i++) {
//                 pubIo[i + 1] = vecToEval1[i];
//             }
//             for (uint i = 0; i < comms.length; i++) {
//                 pubIo[1 + vecToEval1.length + i] = comms[i];
//             }
//         }

//         uint256 padLength = nextPowerOfTwo(pubIoLen); // Built-in nextPowerOfTwo
//         uint256 logPadLength = log2(padLength) ; // Built-in log2

//         uint256[] memory paddedPubIo = new uint256[](padLength);
//         unchecked {
//             for (uint i = 0; i < pubIoLen; i++) {
//                 paddedPubIo[i] = pubIo[i];
//             }
//         }

//         uint256[] memory requiredPt = new uint256[](logPadLength);
//         unchecked {
//             for (uint i = 0; i < logPadLength; i++) {
//                 requiredPt[i] = pt[i + pt.length - logPadLength];
//             }
//         }

//         uint256 computedEval = evaluateMultilinearDotProductOpt(requiredPt, paddedPubIo);
//         uint256 expectedEval = computedEval * compute_random_pts_prod(pt, logPadLength);

//         require(eval == expectedEval, "Evaluation mismatch");
//     }

//     function compute_random_pts_prod(uint256[] memory pt, uint256 logPadLength) public pure returns (uint256) {
//         uint256 product = 1;
//         unchecked {
//             for (uint256 i = 0; i < pt.length - logPadLength; i++) {
//                 product = mulmod(product, MODULUS - pt[i] + 1, MODULUS);
//             }
//         }
//         return product;
//     }

//     function evaluateMultilinearDotProductOpt(
//         uint256[] memory point,
//         uint256[] memory coefficients
//     ) public pure returns (uint256) {
//         uint256 N = point.length;
//         unchecked {
//             for (uint256 j = 0; j < N; j++) {
//                 uint256 stepSize = 1 << (N - j - 1);
//                 for (uint256 i = 0; i < stepSize; i++) {
//                     uint256 left = coefficients[2 * i];
//                     uint256 right = coefficients[2 * i + 1];
//                     coefficients[i] = addmod(
//                         mulmod(left, MODULUS - point[j] + 1, MODULUS),
//                         mulmod(right, point[j], MODULUS),
//                         MODULUS
//                     );
//                 }
//             }
//         }
//         return coefficients[0];
//     }

//     function nextPowerOfTwo(uint256 x) public pure returns (uint256) {
//         if (x == 0) return 1;
//         return 2 ** (log2(x) + 1);
//     }

//     function log2(uint256 x) public pure returns (uint256) {
//         uint256 result = 0;
//         while (x > 1) {
//             x >>= 1;
//             result++;
//         }
//         return result;
//     }
// }
