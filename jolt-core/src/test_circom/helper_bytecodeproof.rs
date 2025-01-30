use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
use core::fmt;

use crate::{jolt::vm::bytecode::BytecodeProof, lasso::memory_checking::MultisetHashes, poly::{commitment::hyperkzg::HyperKZG, unipoly::UniPoly}, subprotocols::grand_product::BatchedGrandProductProof, utils::poseidon_transcript::PoseidonTranscript};
use crate::lasso::memory_checking::StructuredPolynomialData;
use super::{helper_grand_product::{BatchedGrandProductLayerProofCircom, BatchedGrandProductProofCircom}, helper_non_native::{convert_to_3_limbs, Fqq}, helper_sum_check::convert_uni_polys_to_circom};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MultiSethashesCircom {
    pub read_hashes: Vec<Fqq>,
    pub write_hashes: Vec<Fqq>,
    pub init_hashes: Vec<Fqq>,
    pub final_hashes: Vec<Fqq>,
}

impl fmt::Debug for MultiSethashesCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "read_hashes": {:?},
            "write_hashes": {:?},
            "init_hashes": {:?},
            "final_hashes": {:?}
            }}"#,
            self.read_hashes, self.write_hashes, self.init_hashes, self.final_hashes,
        )
    }
}


pub fn convert_multiset_hashes_to_circom(
    multiset_hash: &MultisetHashes<Scalar>,
) -> MultiSethashesCircom {
    let mut read_hashes = Vec::new();

    for i in 0..multiset_hash.read_hashes.len() {
        read_hashes.push(Fqq {
            element: multiset_hash.read_hashes[i].clone(),
            limbs: convert_to_3_limbs(multiset_hash.read_hashes[i].clone()),
        });
    }
    let mut write_hashes = Vec::new();
    for i in 0..multiset_hash.write_hashes.len() {
        write_hashes.push(Fqq {
            element: multiset_hash.write_hashes[i].clone(),
            limbs: convert_to_3_limbs(multiset_hash.write_hashes[i].clone()),
        });
    }
    let mut init_hashes = Vec::new();
    for i in 0..multiset_hash.init_hashes.len() {
        init_hashes.push(Fqq {
            element: multiset_hash.init_hashes[i].clone(),
            limbs: convert_to_3_limbs(multiset_hash.init_hashes[i].clone()),
        });
    }
    let mut final_hashes = Vec::new();
    for i in 0..multiset_hash.final_hashes.len() {
        final_hashes.push(Fqq {
            element: multiset_hash.final_hashes[i].clone(),
            limbs: convert_to_3_limbs(multiset_hash.final_hashes[i].clone()),
        });
    }
    MultiSethashesCircom {
        read_hashes,
        write_hashes,
        init_hashes,
        final_hashes,
    }
}



#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytecodeProofCircom{
    pub multiset_hashes: MultiSethashesCircom,
    pub read_write_grand_product: BatchedGrandProductProofCircom,
    pub init_final_grand_product: BatchedGrandProductProofCircom,
    pub openings: Vec<Fqq>
}

impl fmt::Debug for BytecodeProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        
        write!(
            f,
            r#"{{
            "multiset_hashes": {:?},
            "read_write_grand_product": {:?},
            "init_final_grand_product": {:?},
            "openings": {:?}
            }}"#,
            self.multiset_hashes, self.read_write_grand_product, self.init_final_grand_product, self.openings,
        )
    }
}

pub fn convert_from_batched_GKRProof_to_circom(proof: &BatchedGrandProductProof<HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>) -> BatchedGrandProductProofCircom
{
    let num_gkr_layers = proof.gkr_layers.len();

    let num_coeffs = proof.gkr_layers[num_gkr_layers - 1].proof.uni_polys[0]
    .coeffs
    .len();

    let max_no_polys = proof.gkr_layers[num_gkr_layers - 1].proof.uni_polys.len();

    let mut updated_gkr_layers = Vec::new();

    for idx in 0..num_gkr_layers {
        let zero_poly = UniPoly::from_coeff(vec![Scalar::from(0u8); num_coeffs]);
        let len = proof.gkr_layers[idx].proof.uni_polys.len();
        let updated_uni_poly: Vec<_> = proof.gkr_layers[idx]
            .proof
            .uni_polys
            .clone()
            .into_iter()
            .chain(vec![zero_poly; max_no_polys - len].into_iter())
            .collect();

        updated_gkr_layers.push(BatchedGrandProductLayerProofCircom {
            proof: convert_uni_polys_to_circom(updated_uni_poly),
            left_claim: Fqq {
                element: proof.gkr_layers[idx].left_claim,
                limbs: convert_to_3_limbs(proof.gkr_layers[idx].left_claim),
            },
            right_claim: Fqq {
                element: proof.gkr_layers[idx].right_claim,
                limbs: convert_to_3_limbs(proof.gkr_layers[idx].right_claim),
            },
        });
    }
    // println!("updated_gkr_layers is {:?}", updated_gkr_layers.len());

    BatchedGrandProductProofCircom{
        gkr_layers: updated_gkr_layers
    }
}

pub fn convert_from_bytecode_proof_to_circom(bytecode_proof: BytecodeProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>) -> BytecodeProofCircom{
    let mut openings = Vec::new();
    let previous_openings = bytecode_proof.openings;
    // 8
    for opening in previous_openings.read_write_values() {
        openings.push(Fqq {
            element: opening.clone(),
            limbs: convert_to_3_limbs(opening.clone()),
        });
    }

    // 1
    for opening in previous_openings.init_final_values() {
        openings.push(Fqq {
            element: opening.clone(),
            limbs: convert_to_3_limbs(opening.clone()),
        });
    }
    // 7
    for i in 0..7 {
        openings.push(Fqq {
            element: Scalar::from(0u8),
            limbs: convert_to_3_limbs(Scalar::from(0u8)),
        });
    }
    // Last 7 init_final values will be update inside verifier

    return BytecodeProofCircom{
        multiset_hashes: convert_multiset_hashes_to_circom(&bytecode_proof.multiset_hashes),
        read_write_grand_product: convert_from_batched_GKRProof_to_circom(&bytecode_proof.read_write_grand_product),
        init_final_grand_product: convert_from_batched_GKRProof_to_circom(&bytecode_proof.init_final_grand_product),
        openings: openings
    };
}


