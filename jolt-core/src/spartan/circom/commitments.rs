use std::fmt;

use crate::{poly::commitment::hyperkzg::HyperKZG, poly::commitment::hyrax::{HyraxCommitment, HyraxGenerators, HyraxOpeningProof, HyraxScheme}, spartan::spartan_memory_checking::SpartanCommitments, utils::poseidon_transcript::PoseidonTranscript};
use ark_grumpkin::{Fr as Scalar, Fq as Fp, Projective};
use super::hyrax::hyrax_commitment_to_circom;
use super::hyrax::HyraxCommitmentCircom;

use super::reduced_opening_proof::HyperKZGCommitmentCircom;






pub struct SpartanCommitmentsHyraxCircom{
    pub witness: HyraxCommitmentCircom,
    // pub read_cts_rows: Vec<HyraxCommitmentCircom>,
    // pub read_cts_cols: Vec<HyraxCommitmentCircom>,
    // pub final_cts_rows: Vec<HyraxCommitmentCircom>,
    // pub final_cts_cols: Vec<HyraxCommitmentCircom>,
    // pub rows: Vec<HyraxCommitmentCircom>,
    // pub cols: Vec<HyraxCommitmentCircom>,
    // pub vals: Vec<HyraxCommitmentCircom>,
    // pub e_rx: Vec<HyraxCommitmentCircom>,
    // pub e_ry: Vec<HyraxCommitmentCircom>
}

impl SpartanCommitmentsHyraxCircom{
    pub fn convert(commitments:&SpartanCommitments<HyraxScheme<Projective, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>)->Self{
        Self{
            witness: hyrax_commitment_to_circom(&commitments.witness)
            // read_cts_rows: commitments.read_cts_rows.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // read_cts_cols: commitments.read_cts_cols.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // final_cts_rows: commitments.final_cts_rows.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // final_cts_cols: commitments.final_cts_cols.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // rows: commitments.rows.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // cols: commitments.cols.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // vals: commitments.vals.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // e_rx: commitments.e_rx.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
            // e_ry: commitments.e_ry.iter().map(|com| hyrax_commitment_to_circom(com)).collect(),
        }
    }
}

impl fmt::Debug for SpartanCommitmentsHyraxCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "w_commitment": {:?},
            }}"#,
            self.witness
        
        )
    }
}

