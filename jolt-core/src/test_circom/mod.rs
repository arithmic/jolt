use std::{fs::File, io::Write};
use std::sync::{LazyLock, Mutex};
use common::rv_trace::MemoryLayout;
use helper_joltdevice::{convert_from_jolt_device_to_circom, convert_jolt_proof_to_circom};
use tracer::JoltDevice;

use crate::jolt::vm::rv32i_vm::{RV32ISubtables, RV32I};
use crate::jolt::vm::JoltProof;
use crate::poly::commitment::hyperkzg::HyperKZG;
use crate::r1cs::inputs::{ConstraintInput, JoltR1CSInputs};
use crate::utils::poseidon_transcript::PoseidonTranscript;
use crate::{field::JoltField, host, jolt::vm::{rv32i_vm::{RV32IJoltVM, C, M}, Jolt}, poly::commitment::commitment_scheme::CommitmentScheme, utils::transcript::Transcript};

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

static FIB_FILE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn fib_e2e<F, PCS, ProofTranscript>() -> JoltProof<4, 65536, JoltR1CSInputs, F, PCS, RV32I, RV32ISubtables<F>, ProofTranscript>
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

    let preprocessing = RV32IJoltVM::preprocess(
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
    return proof;
}

use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
#[test]
fn fib_e2e_hyperkzg() {
    println!("Running Fib");
    let proof_from_rust = fib_e2e::<
        Scalar,
        HyperKZG<Bn254, PoseidonTranscript<Fp>>,
        PoseidonTranscript<Fp>,
    >();

    let circom_proof = convert_jolt_proof_to_circom(proof_from_rust);

    let input_json = format!(r#"{{
            "proof": {:?}
        }}"#,
        circom_proof
    );

    let input_file_path = "input.json";
    let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
    input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
    println!("Input JSON file created successfully.");
}