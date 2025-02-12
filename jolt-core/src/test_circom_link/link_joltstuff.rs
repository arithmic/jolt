use core::fmt;
use ark_bn254::{Bn254, Fq as Fp};


use crate::{jolt::vm::{timestamp_range_check::TimestampRangeCheckStuff, JoltStuff}, poly::commitment::hyperkzg::{HyperKZGCommitment, HyperKZGProof, HyperKZGVerifierKey}, r1cs::inputs::{AuxVariableStuff, R1CSStuff}};

use super::{bytecode_stuff::{convert_from_byte_code_stuff_to_circom, ByteCodeStuffCircomLink}, inst_lookups_stuff::{convert_from_ins_lookup_stuff_to_circom, InstructionLookupStuffCircomLink}, link_opening_combiners::{convert_to_3_limbs, Fqq}, rw_stuff::{convert_from_read_write_mem_stuff_to_circom, ReadWriteMemoryStuffCircomLink}};


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct G1AffineCircomLink{
    pub x: Fp,
    pub y: Fp,
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fp2CircomLink{
    pub x: Fp,
    pub y: Fp,
}

impl fmt::Debug for Fp2CircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                                "x": "{}",
                                "y": "{}"
                            }}"#,
            self.x,
            self.y
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct G2AffineCircomLink{
    pub x: Fp2CircomLink,
    pub y: Fp2CircomLink,
}

impl fmt::Debug for G2AffineCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                            "x": {:?},
                            "y": {:?}
                                }}"#,
            self.x,
            self.y
        )
    }
}


impl fmt::Debug for G1AffineCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                            "x": "{}",
                            "y": "{}"
                            }}"#,
            self.x,
            self.y
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyperKZGCommitmentCircomLink{
    pub commitment: G1AffineCircomLink
}

impl fmt::Debug for HyperKZGCommitmentCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "commitment": {:?}
            }}"#,
            self.commitment,
        )
    }
}


pub fn convert_hyperkzg_commitment_to_circom(
    commitment: &HyperKZGCommitment<Bn254>,
) -> HyperKZGCommitmentCircomLink {
    HyperKZGCommitmentCircomLink {
        commitment: G1AffineCircomLink {
            x: commitment.0.x,
            y: commitment.0.y,
        },
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampRangeCheckStuffCircomLink{
    pub read_cts_read_timestamp: Vec<HyperKZGCommitmentCircomLink>,
    pub read_cts_global_minus_read: Vec<HyperKZGCommitmentCircomLink>,
    pub final_cts_read_timestamp: Vec<HyperKZGCommitmentCircomLink>,
    pub final_cts_global_minus_read: Vec<HyperKZGCommitmentCircomLink>,
}

impl fmt::Debug for TimestampRangeCheckStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "read_cts_read_timestamp": {:?},
                "read_cts_global_minus_read": {:?},
                "final_cts_read_timestamp": {:?},
                "final_cts_global_minus_read": {:?}
            }}"#,
            self.read_cts_read_timestamp, self.read_cts_global_minus_read, self.final_cts_read_timestamp, self.final_cts_global_minus_read
        )
    }
}

pub fn convert_from_ts_lookup_stuff_to_circom(ts_lookup_stuff: &TimestampRangeCheckStuff<HyperKZGCommitment<Bn254>>) -> TimestampRangeCheckStuffCircomLink{

    let mut read_cts_read_timestamp = Vec::new();
    let mut read_cts_global_minus_read = Vec::new();
    let mut final_cts_read_timestamp = Vec::new();
    let mut final_cts_global_minus_read = Vec::new();
    for i in 0..ts_lookup_stuff.read_cts_read_timestamp.len(){
        read_cts_read_timestamp.push(convert_hyperkzg_commitment_to_circom(&ts_lookup_stuff.read_cts_read_timestamp[i].clone()))
    }
    for i in 0..ts_lookup_stuff.read_cts_global_minus_read.len(){
        read_cts_global_minus_read.push(convert_hyperkzg_commitment_to_circom(&ts_lookup_stuff.read_cts_global_minus_read[i].clone()));
    }
    for i in 0..ts_lookup_stuff.final_cts_read_timestamp.len(){
        final_cts_read_timestamp.push(convert_hyperkzg_commitment_to_circom(&ts_lookup_stuff.final_cts_read_timestamp[i].clone()));
    }
    for i in 0..ts_lookup_stuff.final_cts_global_minus_read.len(){
        final_cts_global_minus_read.push(convert_hyperkzg_commitment_to_circom(&ts_lookup_stuff.final_cts_global_minus_read[i].clone()));
    }


    TimestampRangeCheckStuffCircomLink{
        read_cts_read_timestamp,
        read_cts_global_minus_read,
        final_cts_read_timestamp,
        final_cts_global_minus_read,
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuxVariableStuffCircomLink{
    pub left_lookup_operand: HyperKZGCommitmentCircomLink,
    pub right_lookup_operand: HyperKZGCommitmentCircomLink,
    pub product: HyperKZGCommitmentCircomLink,
    pub relevant_y_chunks: Vec<HyperKZGCommitmentCircomLink>,
    pub write_lookup_output_to_rd: HyperKZGCommitmentCircomLink,
    pub write_pc_to_rd: HyperKZGCommitmentCircomLink,
    pub next_pc_jump: HyperKZGCommitmentCircomLink,
    pub should_branch: HyperKZGCommitmentCircomLink,
    pub next_pc: HyperKZGCommitmentCircomLink

}

impl fmt::Debug for AuxVariableStuffCircomLink {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                r#"{{
                    "left_lookup_operand": {:?},
                    "right_lookup_operand": {:?},
                    "product": {:?},
                    "relevant_y_chunks": {:?},
                    "write_lookup_output_to_rd": {:?},
                    "write_pc_to_rd": {:?},
                    "next_pc_jump": {:?},
                    "should_branch": {:?},
                    "next_pc": {:?}
                }}"#,
                self.left_lookup_operand, self.right_lookup_operand, self.product, self.relevant_y_chunks, self.write_lookup_output_to_rd, self.write_pc_to_rd, self.next_pc_jump, self.should_branch, self.next_pc
            )
        }
    }


    pub fn convert_from_aux_stuff_to_circom(aux_stuff: &AuxVariableStuff<HyperKZGCommitment<Bn254>>) -> AuxVariableStuffCircomLink{
        let mut relevant_y_chunks = Vec::new();
        for i in 0..aux_stuff.relevant_y_chunks.len(){
            relevant_y_chunks.push(convert_hyperkzg_commitment_to_circom(&aux_stuff.relevant_y_chunks[i].clone()))
        }
        AuxVariableStuffCircomLink{
            left_lookup_operand: convert_hyperkzg_commitment_to_circom(&aux_stuff.left_lookup_operand),
            right_lookup_operand: convert_hyperkzg_commitment_to_circom(&aux_stuff.right_lookup_operand),
            product: convert_hyperkzg_commitment_to_circom(&aux_stuff.product),
            relevant_y_chunks: relevant_y_chunks,
            write_lookup_output_to_rd: convert_hyperkzg_commitment_to_circom(&aux_stuff.write_lookup_output_to_rd),
            write_pc_to_rd: convert_hyperkzg_commitment_to_circom(&aux_stuff.write_pc_to_rd),
            next_pc_jump: convert_hyperkzg_commitment_to_circom(&aux_stuff.next_pc_jump),
            should_branch: convert_hyperkzg_commitment_to_circom(&aux_stuff.should_branch),
            next_pc: convert_hyperkzg_commitment_to_circom(&aux_stuff.next_pc)
        }
    }

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct R1CSStuffCircomLink{
    pub chunks_x: Vec<HyperKZGCommitmentCircomLink>,
    pub chunks_y: Vec<HyperKZGCommitmentCircomLink>,
    pub circuit_flags: Vec<HyperKZGCommitmentCircomLink>,
    pub aux: AuxVariableStuffCircomLink,
}

impl fmt::Debug for R1CSStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "chunks_x": {:?},
                "chunks_y": {:?},
                "circuit_flags": {:?},
                "aux": {:?}
            }}"#,
            self.chunks_x, self.chunks_y, self.circuit_flags, self.aux
        )
    }
}

pub fn convert_from_r1cs_stuff_to_circom(r1cs_stuff: &R1CSStuff<HyperKZGCommitment<Bn254>>) -> R1CSStuffCircomLink{
    let mut chunks_x = Vec::new();
    let mut chunks_y = Vec::new();
    let mut circuit_flags = Vec::new();
    for i in 0..r1cs_stuff.chunks_x.len(){
        chunks_x.push(convert_hyperkzg_commitment_to_circom(&r1cs_stuff.chunks_x[i].clone()));
    }
    for i in 0..r1cs_stuff.chunks_y.len(){
        chunks_y.push(convert_hyperkzg_commitment_to_circom(&r1cs_stuff.chunks_y[i].clone()));
    }
    for i in 0..r1cs_stuff.circuit_flags.len(){
        circuit_flags.push(convert_hyperkzg_commitment_to_circom(&r1cs_stuff.circuit_flags[i].clone()));
    }
    R1CSStuffCircomLink{
        chunks_x,
        chunks_y,
        circuit_flags,
        aux: convert_from_aux_stuff_to_circom(&r1cs_stuff.aux),
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct JoltStuffCircomLink{
    pub bytecode: ByteCodeStuffCircomLink,
    pub read_write_memory: ReadWriteMemoryStuffCircomLink,
    pub instruction_lookups: InstructionLookupStuffCircomLink,
    pub timestamp_range_check: TimestampRangeCheckStuffCircomLink,
    pub r1cs: R1CSStuffCircomLink
}

impl fmt::Debug for JoltStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {


        write!(
            f,
            r#"{{
                "bytecode": {:?},
                "read_write_memory": {:?},
                "instruction_lookups": {:?},
                "timestamp_range_check": {:?},
                "r1cs": {:?}
        }}"#,
            self.bytecode, self.read_write_memory, self.instruction_lookups, self.timestamp_range_check, self.r1cs
        )
    }
}

pub fn convert_from_jolt_stuff_to_circom_for_linking(jolt_stuff: &JoltStuff<HyperKZGCommitment<Bn254>>) -> JoltStuffCircomLink{
    JoltStuffCircomLink{
        bytecode: convert_from_byte_code_stuff_to_circom(&jolt_stuff.bytecode),
        read_write_memory: convert_from_read_write_mem_stuff_to_circom(&jolt_stuff.read_write_memory),
        instruction_lookups: convert_from_ins_lookup_stuff_to_circom(&jolt_stuff.instruction_lookups),
        timestamp_range_check: convert_from_ts_lookup_stuff_to_circom(&jolt_stuff.timestamp_range_check),
        r1cs: convert_from_r1cs_stuff_to_circom(&jolt_stuff.r1cs)
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct KZGVerifierKeyCircomLink{
    pub g1: G1AffineCircomLink,
    pub g2: G2AffineCircomLink,
    pub beta_g2: G2AffineCircomLink
}

impl fmt::Debug for KZGVerifierKeyCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                        "g1": {:?},
                        "g2": {:?},
                        "beta_g2": {:?}
            }}"#,
            self.g1,
            self.g2,
            self.beta_g2,
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyperKZGVerifierKeyCircomLink{
    pub kzg_vk: KZGVerifierKeyCircomLink,
}


impl fmt::Debug for HyperKZGVerifierKeyCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                    "kzg_vk": {:?}
            }}"#,
            self.kzg_vk
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyperKZGProofCircomLink{
    pub com: Vec<G1AffineCircomLink>,
    pub w: [G1AffineCircomLink; 3],
    pub v: [Vec<Fqq>; 3],
}


impl fmt::Debug for HyperKZGProofCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                    "com": {:?},
                    "w": [ {:?}, {:?}, {:?} ],
                    "v": {:?}
            }}"#,
            self.com,
            self.w[0], self.w[1], self.w[2],
            self.v

        )
    }
}

pub fn hyper_kzg_proof_to_hyper_kzg_circomfor_linking(proof: &HyperKZGProof<Bn254>) -> HyperKZGProofCircomLink {
    let com: Vec<G1AffineCircomLink> = proof
        .com
        .iter()
        .map(|c| G1AffineCircomLink { x: c.x, y: c.y })
        .collect();

    let w = proof
        .w
        .iter()
        .map(|wi| G1AffineCircomLink { x: wi.x, y: wi.y })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut v: [Vec<Fqq>; 3] = Default::default();
    for i in 0..proof.v.len() {
        for j in 0..proof.v[i].len() {
            v[i].push(Fqq {
                element: proof.v[i][j],
                limbs: convert_to_3_limbs(proof.v[i][j]),
            })
        }
    }
    HyperKZGProofCircomLink { com, w, v }
}

pub fn convert_hyperkzg_verifier_key_to_hyperkzg_verifier_key_circom_for_linking(
    vk: HyperKZGVerifierKey<Bn254>,
) -> HyperKZGVerifierKeyCircomLink {
    HyperKZGVerifierKeyCircomLink {
        kzg_vk: KZGVerifierKeyCircomLink {
            g1: G1AffineCircomLink {
                x: vk.kzg_vk.g1.x,
                y: vk.kzg_vk.g1.y,
            },
            g2: G2AffineCircomLink {
                x: Fp2CircomLink {
                    x: vk.kzg_vk.g2.x.c0,
                    y: vk.kzg_vk.g2.x.c1,
                },
                y: Fp2CircomLink {
                    x: vk.kzg_vk.g2.y.c0,
                    y: vk.kzg_vk.g2.y.c1,
                },
            },
            beta_g2: G2AffineCircomLink {
                x: Fp2CircomLink {
                    x: vk.kzg_vk.beta_g2.x.c0,
                    y: vk.kzg_vk.beta_g2.x.c1,
                },
                y: Fp2CircomLink {
                    x: vk.kzg_vk.beta_g2.y.c0,
                    y: vk.kzg_vk.beta_g2.y.c1,
                },
            },
        },
    }
}