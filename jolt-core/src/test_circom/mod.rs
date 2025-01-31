use std::{fs::File, io::Write};
use std::sync::{LazyLock, Mutex};
use common::rv_trace::MemoryLayout;
use helper_joltdevice::{convert_from_jolt_device_to_circom, convert_jolt_proof_to_circom, JoltproofCircom};
use helper_preprocessing::{convert_joltpreprocessing_to_circom, JoltPreprocessingCircom};
use helper_stuff::{convert_from_jolt_stuff_to_circom, JoltStuffCircom};
use helper_transcript::convert_transcript_to_circom;
use tracer::JoltDevice;
use crate::jolt::vm::rv32i_vm::{RV32ISubtables, RV32I};
use crate::jolt::vm::{JoltPreprocessing, JoltProof, JoltStuff};
use crate::poly::commitment::hyperkzg::{HyperKZG, HyperKZGCommitment};
use crate::r1cs::inputs::{ConstraintInput, JoltR1CSInputs};
use crate::utils::poseidon_transcript::PoseidonTranscript;
use crate::{field::JoltField, host, jolt::vm::{rv32i_vm::{RV32IJoltVM, C, M}, Jolt}, poly::commitment::commitment_scheme::CommitmentScheme, utils::transcript::Transcript};
pub mod helper_preprocessing;
pub mod helper_non_native;
pub mod helper_sum_check;
pub mod helper_bytecodeproof;
pub mod helper_grand_product;
pub mod helper_hyperkzg;
pub mod helper_joltdevice;
pub mod helper_read_write_mem_proof;
pub mod helper_reduced_opening_proof;
pub mod helper_transcript;
pub mod helper_uni_spartan_proof;
pub mod helper_stuff;


static FIB_FILE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
#[test]
fn fib_e2e_hyperkzg() {
    println!("Running Fib");
    let (preprocessing, proof_from_rust, commitments) = fib_e2e::<
        Scalar,
        HyperKZG<Bn254, PoseidonTranscript<Fp>>,
        PoseidonTranscript<Fp>,
    >();
  
    let (circom_preprocessing, circom_proof, circom_stuff) = convert_full_proof_to_circom(preprocessing, proof_from_rust, commitments);

    //         
    let mut transcipt_init = <PoseidonTranscript<Fp> as Transcript>::new(b"Jolt transcript");

    let input_json = format!(
        r#"{{
        "transcript_init": {:?},
        "preprocessing": {:?},
        "proof": {:?},
        "commitments": {:?}
    }}"#,
        convert_transcript_to_circom(transcipt_init),
        circom_preprocessing,
        circom_proof,
        circom_stuff
    );

    let input_file_path = "input.json";
    let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
    input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
    println!("Input JSON file created successfully.");
}


fn fib_e2e<F, PCS, ProofTranscript>() -> (JoltPreprocessing<C, F, PCS, ProofTranscript>, JoltProof<4, 65536, JoltR1CSInputs, F, PCS, RV32I, RV32ISubtables<F>, ProofTranscript>, JoltStuff<<PCS as CommitmentScheme<ProofTranscript>>::Commitment>)
where
    F: JoltField,
    PCS: CommitmentScheme<ProofTranscript, Field = F>,
    ProofTranscript: Transcript,
{
    let artifact_guard = FIB_FILE_LOCK.lock().unwrap();
    let mut program = host::Program::new("fibonacci-guest");
    program.set_input(&9u32);
    let (bytecode, memory_init) = program.decode();
    let (io_device, trace) = program.trace();
    drop(artifact_guard);

    let preprocessing: JoltPreprocessing<C, F, PCS, ProofTranscript> = RV32IJoltVM::preprocess(
        bytecode.clone(),
        io_device.memory_layout.clone(),
        memory_init,
        1 << 20,
        1 << 20,
        1 << 20,
    );
    let (proof, commitments, debug_info) =
        <RV32IJoltVM as Jolt<F, PCS, C, M, ProofTranscript>>::prove(
            io_device,
            trace,
            preprocessing.clone(),
        );

    // println!("bytecode stuff is {:?}", commitments.bytecode.a_read_write);
    // let verification_result =
    //     RV32IJoltVM::verify(preprocessing, proof, commitments, debug_info);
    // assert!(
    //     verification_result.is_ok(),
    //     "Verification failed with error: {:?}",
    //     verification_result.err()
    // );
    return (preprocessing, proof, commitments);
}


pub fn convert_full_proof_to_circom(
    jolt_preprocessing: JoltPreprocessing<C, Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>,PoseidonTranscript<Fp>>,
    jolt_proof: JoltProof<{C}, {M}, JoltR1CSInputs, Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, RV32I, RV32ISubtables<Scalar>, PoseidonTranscript<Fp>>,
    jolt_stuff: JoltStuff<HyperKZGCommitment<Bn254>>
) -> (JoltPreprocessingCircom, JoltproofCircom, JoltStuffCircom) {

    (
        convert_joltpreprocessing_to_circom(jolt_preprocessing),
        convert_jolt_proof_to_circom(jolt_proof),
        convert_from_jolt_stuff_to_circom(jolt_stuff),
    )
}

#[test]
fn test_formatting_jolt_device() {
    let mem_layout = MemoryLayout::new(5, 10);

    let jolt_device = JoltDevice {
        inputs: [3, 4, 5].to_vec(),
        outputs: [3, 4, 5].to_vec(),
        panic: false,
        memory_layout: mem_layout,
    };

    let jolt_device_circom = convert_from_jolt_device_to_circom(jolt_device);

    let input_json = format!(
        r#"{{
            "program_io": {:?}
        }}"#,
        jolt_device_circom
    );
    let input_file_path = "input.json";
    let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
    input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
    println!("Input JSON file created successfully.");
}

#[test]
fn test_fib(){
    let artifact_guard = FIB_FILE_LOCK.lock().unwrap();
    let mut program = host::Program::new("fibonacci-guest");
    program.set_input(&9u32);
    let (bytecode, memory_init) = program.decode();
    let (io_device, trace) = program.trace();
    drop(artifact_guard);

    let preprocessing: JoltPreprocessing<C, Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>> = RV32IJoltVM::preprocess(
        bytecode.clone(),
        io_device.memory_layout.clone(),
        memory_init,
        1 << 20,
        1 << 20,
        1 << 20,
    );
    let (proof, commitments, debug_info) =
    <RV32IJoltVM as Jolt<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, C, M, PoseidonTranscript<Fp>>>::prove(
        io_device,
        trace,
        preprocessing.clone(),
    );
}

