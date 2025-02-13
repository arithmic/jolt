mod grand_product;
mod memory_check;
mod non_native;
mod reduced_opening_proof;
mod sum_check;
mod transcript;
mod spartan_proof;
mod public_input;
mod commitments;
use std::{fs::File, io::Write};

use ark_bn254::{ Bn254, Fr as Scalar, Fq as Fp };
use commitments::SpartanCommitmentsCircom;
use non_native::convert_vec_to_fqq;
use reduced_opening_proof::convert_hyperkzg_verifier_key_to_hyperkzg_verifier_key_circom;
use spartan_proof::{preprocessing_to_pi_circom, SpartanProofCircom};
use transcript::convert_transcript_to_circom;

use crate::{
    poly::commitment::{ commitment_scheme::CommitmentScheme, hyperkzg::HyperKZG },
    utils::{poseidon_transcript::PoseidonTranscript, transcript::Transcript},
};
use super::spartan_memory_checking::{ SpartanPreprocessing, SpartanProof };

use super::*;

pub type ProofTranscript = PoseidonTranscript<Fp>;
pub type PCS = HyperKZG<Bn254, ProofTranscript>;
#[test]
fn parse_spartan() {
    let mut preprocessing = SpartanPreprocessing::<Scalar>::preprocess(None, None, 2);
    let commitment_shapes = SpartanProof::<Scalar, PCS, ProofTranscript>::commitment_shapes(
        preprocessing.inputs.len() + preprocessing.vars.len()
    );
    let pcs_setup = PCS::setup(&commitment_shapes);
    let (mut spartan_polynomials, mut spartan_commitments) = SpartanProof::<
        Scalar,
        PCS,
        ProofTranscript
    >::generate_witness(&preprocessing, &pcs_setup);

    let proof = SpartanProof::<Scalar, PCS, ProofTranscript>::prove(
        &pcs_setup,
        &mut spartan_polynomials,
        &mut spartan_commitments,
        &mut preprocessing
    );

    let mut transcipt_init = <PoseidonTranscript<Fp> as Transcript>::new(b"Spartan transcript");

    let input_json = format!(
        r#"{{
        "pub_inp": {:?},
        "vk": {:?},
        "proof": {:?},
        "commits": {:?},
        "transcript": {:?}
    }}"#,
        preprocessing_to_pi_circom(&preprocessing),
        convert_hyperkzg_verifier_key_to_hyperkzg_verifier_key_circom(pcs_setup.1),
        SpartanProofCircom::parse_spartan_proof(&proof),
        SpartanCommitmentsCircom::convert(&spartan_commitments),
        convert_transcript_to_circom(transcipt_init)
    );

    let input_file_path = "input.json";
    let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
    input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
    println!("Input JSON file created successfully.");
    

    SpartanProof::<Scalar, PCS, ProofTranscript>
    ::verify(&pcs_setup, &preprocessing, &spartan_commitments, proof)
    .unwrap();
}
