use core::fmt;

use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
use common::rv_trace::{JoltDevice, MemoryLayout};

use crate::{jolt::vm::{rv32i_vm::{RV32ISubtables, C, M, RV32I}, JoltProof}, poly::commitment::hyperkzg::HyperKZG, r1cs::inputs::JoltR1CSInputs, utils::poseidon_transcript::PoseidonTranscript};

use super::{helper_bytecodeproof::{convert_from_bytecode_proof_to_circom, BytecodeProofCircom}, helper_read_write_mem_proof::{convert_from_read_write_mem_proof_to_circom, convert_reduced_opening_proof_to_circom, ReadWriteMemoryProofCircom}, helper_reduced_opening_proof::ReducedOpeningProofCircom, helper_uni_spartan_proof::{compute_uniform_spartan_to_circom, UniformSpartanProofCircom}};
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryLayoutCircom {
    max_input_size: Fp,
    max_output_size: Fp,
    input_start: Fp,
    input_end: Fp,
    output_start: Fp,
    output_end: Fp,
    panic: Fp,
    termination: Fp,
}

impl fmt::Debug for MemoryLayoutCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                        "max_input_size": "{}",
                        "max_output_size": "{}",
                        "input_start": "{}",
                        "input_end": "{}",
                        "output_start": "{}",
                        "output_end": "{}",
                        "panic": "{}",
                        "termination": "{}"
                    }}"#,
            self.max_input_size,
            self.max_output_size,
            self.input_start,
            self.input_end,
            self.output_start,
            self.output_end,
            self.panic,
            self.termination
        )
    }
}

pub fn convert_from_memory_layout_to_circom(mem_layput: MemoryLayout) -> MemoryLayoutCircom {
    MemoryLayoutCircom {
        max_input_size: Fp::from(mem_layput.max_input_size),
        max_output_size: Fp::from(mem_layput.max_output_size),
        input_start: Fp::from(mem_layput.input_start),
        input_end: Fp::from(mem_layput.input_end),
        output_start: Fp::from(mem_layput.output_start),
        output_end: Fp::from(mem_layput.output_end),
        panic: Fp::from(mem_layput.panic),
        termination: Fp::from(mem_layput.termination),
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct JoltDeviceCircom {
    inputs: Vec<Fp>,
    outputs: Vec<Fp>,
    panic: Fp,
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fpcircom(Fp);

impl fmt::Debug for Fpcircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#""{}""#, self.0)
    }
}
pub struct VecFP {
    pub vec: Vec<Fpcircom>,
}
impl fmt::Debug for VecFP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"{:?}"#, self.vec)
    }
}

impl fmt::Debug for JoltDeviceCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                    "inputs": {:?},
                    "outputs": {:?},
                    "panic": "{}"
            }}"#,
            vec_fp_to_vec_fpcircom(self.inputs.clone()),
            vec_fp_to_vec_fpcircom(self.outputs.clone()),
            self.panic
        )
    }
}

pub fn convert_from_jolt_device_to_circom(jolt_device: JoltDevice) -> JoltDeviceCircom {
    JoltDeviceCircom {
        inputs: jolt_device.inputs.into_iter().map(Fp::from).collect(),
        outputs: jolt_device.outputs.into_iter().map(Fp::from).collect(),
        panic: Fp::from(jolt_device.panic as u64),
    }
}

pub fn vec_fp_to_vec_fpcircom(vec: Vec<Fp>) -> Vec<Fpcircom> {
    vec.into_iter().map(Fpcircom).collect()
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct JoltproofCircom{
    pub trace_length: Fp,
    pub program_io: JoltDeviceCircom,
    pub bytecode: BytecodeProofCircom,
    pub read_write_memory: ReadWriteMemoryProofCircom,
    pub r1cs: UniformSpartanProofCircom,
    pub opening_proof: ReducedOpeningProofCircom
}

impl fmt::Debug for JoltproofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "trace_length": "{}",
            "program_io": {:?},
            "bytecode": {:?},
            "read_write_memory": {:?},
            "opening_proof": {:?}
            }}"#,
            self.trace_length, self.program_io, self.bytecode, self.read_write_memory, self.opening_proof
        )
    }
}

pub fn convert_jolt_proof_to_circom(proof: JoltProof<{C}, {M}, JoltR1CSInputs, Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, RV32I, RV32ISubtables<Scalar>, PoseidonTranscript<Fp>>) -> JoltproofCircom{
    JoltproofCircom{
        trace_length: Fp::from(proof.trace_length as u128),
        program_io: convert_from_jolt_device_to_circom(proof.program_io),
        bytecode: convert_from_bytecode_proof_to_circom(proof.bytecode),
        read_write_memory: convert_from_read_write_mem_proof_to_circom(proof.read_write_memory),
        r1cs: compute_uniform_spartan_to_circom(proof.r1cs),
        opening_proof: convert_reduced_opening_proof_to_circom(proof.opening_proof)
    }
}

