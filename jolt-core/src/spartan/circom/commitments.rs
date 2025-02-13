use std::fmt;

use crate::{poly::commitment::hyperkzg::HyperKZG, spartan::spartan_memory_checking::SpartanCommitments, utils::poseidon_transcript::PoseidonTranscript};
use ark_bn254::Bn254;
use ark_bn254::Fr as Scalar;
use ark_bn254::Fq as Fp;
use super::reduced_opening_proof::convert_hyperkzg_commitment_to_circom;
use super::reduced_opening_proof::HyperKZGCommitmentCircom;



pub struct SpartanCommitmentsCircom{
    pub witness: HyperKZGCommitmentCircom,
    pub read_cts_rows: Vec<HyperKZGCommitmentCircom>,
    pub read_cts_cols: Vec<HyperKZGCommitmentCircom>,
    pub final_cts_rows: Vec<HyperKZGCommitmentCircom>,
    pub final_cts_cols: Vec<HyperKZGCommitmentCircom>,
    pub rows: Vec<HyperKZGCommitmentCircom>,
    pub cols: Vec<HyperKZGCommitmentCircom>,
    pub vals: Vec<HyperKZGCommitmentCircom>,
    pub e_rx: Vec<HyperKZGCommitmentCircom>,
    pub e_ry: Vec<HyperKZGCommitmentCircom>
}

impl SpartanCommitmentsCircom{
    pub fn convert(commitments:&SpartanCommitments<HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>){

        Self{
            witness: convert_hyperkzg_commitment_to_circom(&commitments.witness),
            read_cts_rows: commitments.read_cts_rows.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            read_cts_cols: commitments.read_cts_cols.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            final_cts_rows: commitments.final_cts_rows.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            final_cts_cols: commitments.final_cts_cols.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            rows: commitments.rows.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            cols: commitments.cols.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            vals: commitments.vals.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            e_rx: commitments.e_rx.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
            e_ry: commitments.e_ry.iter().map(|com| convert_hyperkzg_commitment_to_circom(com)).collect(),
        };
    }
}

impl fmt::Debug for SpartanCommitmentsCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "w": {:?},
            "val": {:?},
            "row": {:?},
            "col": {:?},
            "read_ts_row": {:?},
            "read_ts_col": {:?},
            "final_ts_row": {:?},
            "final_ts_col": {:?},
            "e_row": {:?},
            "e_col": {:?},
            }}"#,
            self.witness,
            self.vals,
            self.rows,
            self.cols,
            self.read_cts_rows,
            self.read_cts_cols,
            self.final_cts_rows,
            self.final_cts_cols,
            self.e_rx,
            self.e_ry,
        )
    }
}

