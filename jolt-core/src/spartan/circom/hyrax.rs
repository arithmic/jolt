use std::fmt;

use ark_bn254::Bn254;
use ark_bn254::G1Projective;

use crate::poly::commitment;
use crate::poly::commitment::hyrax::HyraxCommitment;
use crate::poly::commitment::hyrax::HyraxOpeningProof;
use crate::poly::commitment::pedersen::PedersenGenerators;
use crate::utils::poseidon_transcript::PoseidonTranscript;

use super::non_native::convert_to_3_limbs;
use super::non_native::convert_vec_to_fqq;
use super::non_native::Fqq;
use ark_bn254::Fq as Fp;
use ark_bn254::Fr as Scalar;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyraxGensCircom(pub Vec<G1Circom>);
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyraxCommitmentCircom(pub Vec<G1Circom>);
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]pub struct HyraxEvalProofCircom(pub Vec<Fqq>);

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct G1Circom {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl G1Circom {
    pub fn from_g1(elem: &G1Projective) -> G1Circom {
        G1Circom {
            x: elem.x,
            y: elem.y,
            z: elem.z,
        }
    }
}
impl fmt::Debug for G1Circom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "x": "{:}",
                "y": "{:}",
                "z": "{:}"
            }}"#,
            self.x, self.y, self.z,
        )
    }
}

impl fmt::Debug for HyraxGensCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "gens": {:?}
            }}"#,
            self.0
        )
    }
}


impl fmt::Debug for HyraxCommitmentCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "row_commitments": {:?}
            }}"#,
            self.0
        )
    }
}

impl fmt::Debug for HyraxEvalProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "tau": {:?}
            }}"#,
            self.0
        )
    }
}

pub fn hyrax_gens_to_circom(gens: &PedersenGenerators<G1Projective>) -> HyraxGensCircom {
    HyraxGensCircom(
        gens.generators
            .iter()
            .map(|g| G1Circom::from_g1(&G1Projective::from(*g)))
            .collect(),
    )
}

pub fn hyrax_commitment_to_circom(commit: &HyraxCommitment<G1Projective>)-> HyraxCommitmentCircom{
    HyraxCommitmentCircom(commit.row_commitments.iter().map(|g| G1Circom::from_g1(
        &G1Projective::from(*g)
     )).collect())
}

pub fn hyrax_eval_proof_to_circom(eval_proof: &HyraxOpeningProof<G1Projective, PoseidonTranscript<Fp>>)-> HyraxEvalProofCircom{
    HyraxEvalProofCircom(convert_vec_to_fqq(&eval_proof.vector_matrix_product))
}