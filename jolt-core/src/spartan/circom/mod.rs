mod grand_product;
mod memory_check;
mod non_native;
mod reduced_opening_proof;
mod sum_check;
mod transcript;
mod spartan_proof;
mod public_input;
mod commitments;
mod hyrax;
use std::{convert, fs::File, io::Write};
// use ark_bn254::{ Bn254, Fq as Fp, Fr as Scalar, G1Projective };
use ark_grumpkin::{Fr as GrumpkinScalar, Fq as GrumpkinBase, Projective};
use ark_crypto_primitives::sponge::poseidon::{get_poseidon_parameters, PoseidonDefaultConfigEntry};
use ark_ff::PrimeField;
use commitments::{ SpartanCommitmentsHyraxCircom};
use hyrax::{hyrax_commitment_to_circom, hyrax_gens_to_circom};
use non_native::{convert_from_3_limbs, convert_vec_to_fqq};
use ark_ec::AdditiveGroup;
use spartan_proof::{preprocessing_to_pi_circom, SpartanProofHyraxCircom};
use transcript::convert_transcript_to_circom;

use crate::{
    poly::commitment::{ commitment_scheme::CommitmentScheme, hyperkzg::HyperKZG, hyrax::HyraxScheme },
    utils::{poseidon_transcript::{GrumpkinPoseidonTranscript, PoseidonTranscript}, transcript::Transcript},
};
use super::spartan_memory_checking::{ SpartanPreprocessing, SpartanProof };
use super::*;

#[test]
fn parse_spartan_hyrax() {
    type ProofTranscript = GrumpkinPoseidonTranscript<GrumpkinBase>;
    type PCS = HyraxScheme<Projective, ProofTranscript>;
    let mut preprocessing = SpartanPreprocessing::<GrumpkinScalar>::preprocess(None, None, 2);
    let commitment_shapes = SpartanProof::<GrumpkinScalar, PCS, ProofTranscript>::commitment_shapes(
        preprocessing.inputs.len() + preprocessing.vars.len()
    );
    // println!("commitment_shapes is {:?}",commitment_shapes);

    let pcs_setup = PCS::setup(&commitment_shapes);
    let (mut spartan_polynomials, mut spartan_commitments) = SpartanProof::<
        GrumpkinScalar,
        PCS,
        ProofTranscript
    >::generate_witness(&preprocessing, &pcs_setup);
     println!("pub_inp_len is {}",preprocessing.inputs.len());
     // println!("num_vars is {}",preprocessing.vars.len());

    let proof = SpartanProof::<GrumpkinScalar, PCS, ProofTranscript>::prove(
        &pcs_setup,
        // &mut spartan_polynomials,
        // &mut spartan_commitments,
        &mut preprocessing
    );

     // println!("w_num_commitments is {}",proof.witness_commit.row_commitments.len());
    let mut transcipt_init = <GrumpkinPoseidonTranscript<GrumpkinBase> as Transcript>::new(b"Spartan transcript");

    let input_json = format!(
        r#"{{
        "pub_inp": {:?},
        "setup": {:?},
        "proof": {:?},
        "w_commitment": {:?},
        "transcript": {:?}
    }}"#,
        preprocessing_to_pi_circom(&preprocessing),
        hyrax_gens_to_circom(&pcs_setup , &proof ),
        SpartanProofHyraxCircom::parse_spartan_proof(&proof),
        hyrax_commitment_to_circom(&proof.witness_commit),
        convert_transcript_to_circom(transcipt_init)
    );

  
    let input_file_path = "input.json";
    let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
    input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
    println!("Input JSON file created successfully.");
    

    SpartanProof::<GrumpkinScalar, PCS, ProofTranscript>
    ::verify(&pcs_setup, &preprocessing, proof)
    .unwrap();



}




#[test]
fn testing_sum_check(){
    let a: [u128 ;3 ] =[29392775318536252837192766827518890471, 33875377551868025514534933081038980578, 13];
    let mut vec = [GrumpkinBase::ZERO; 3];
    for i in 0..3{
        vec[i] = GrumpkinBase::from(a[i]);
    }

    let r = convert_from_3_limbs(vec.to_vec());

    println!("r is {}",r);


    
}