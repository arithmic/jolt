use core::fmt;
use std::{fs::File, io::Write};
use std::fmt::Write as fmt_write;
use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};
use common::rv_trace::{JoltDevice, MemoryLayout};
use crate::lasso::memory_checking::StructuredPolynomialData;
use crate::jolt::vm::instruction_lookups::{InstructionLookupsProof, PrimarySumcheckOpenings};
use crate::jolt::vm::read_write_memory::ReadWriteMemoryProof;
use crate::poly::commitment::hyperkzg::HyperKZG;
use crate::poly::opening_proof::ReducedOpeningProof;
use crate::utils::poseidon_transcript::PoseidonTranscript;

use super::helper_bytecodeproof::{convert_from_batched_GKRProof_to_circom, convert_multiset_hashes_to_circom, MultiSethashesCircom};
use super::helper_grand_product::BatchedGrandProductProofCircom;
use super::helper_hyperkzg::hyper_kzg_proof_to_hyper_kzg_circom;
use super::helper_non_native::{convert_to_3_limbs, Fqq};
use super::helper_reduced_opening_proof::ReducedOpeningProofCircom;
use super::helper_sum_check::{convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom};
use crate::jolt::vm::rv32i_vm::{RV32ISubtables, C, M, RV32I};
// use jolt_core::jolt::instruction::JoltInstructionSet;
// use jolt_core::jolt::subtable::JoltSubtableSet;
// use jolt_core::jolt::vm::instruction_lookups::{InstructionLookupsProof, PrimarySumcheckOpenings};
// use jolt_core::jolt::vm::read_write_memory::{ReadWriteMemoryStuff, RegisterAddressOpenings};
// use jolt_core::jolt::vm::rv32i_vm::{RV32ISubtables, M, C, RV32I};
// use jolt_core::jolt::vm::timestamp_range_check::TimestampValidityProof;
// use jolt_core::poly::opening_proof::ReducedOpeningProof;
// use jolt_core::{jolt::vm::read_write_memory::ReadWriteMemoryProof, poly::commitment::hyperkzg::HyperKZG, utils::poseidon_transcript::PoseidonTranscript};

// use jolt_core::lasso::memory_checking::{MemoryCheckingProof, StructuredPolynomialData};
// use crate::helper_bytecodeproof::{convert_from_batched_GKRProof_to_circom, convert_multiset_hashes_to_circom, MultiSethashesCircom};
// use crate::helper_grand_product::BatchedGrandProductProofCircom;
// use crate::helper_hyperkzg::hyper_kzg_proof_to_hyper_kzg_circom;
// use crate::helper_non_native::{convert_to_3_limbs, Fqq};
// use crate::helper_reduced_opening_proof::ReducedOpeningProofCircom;
// use crate::helper_sum_check::{convert_sum_check_proof_to_circom, SumcheckInstanceProofCircom};
// use crate::helper_uni_spartan_proof::ReducedOpeningProofCircom;
// use sum_check::helper::convert_sum_check_proof_to_circom;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadWriteMemoryProofCircom{
    pub memory_checking_proof: ReadWriteMemoryCheckingProofCircom,
    pub timestamp_validity_proof: TimestampValidityProofCircom,
    pub output_proof: OutputSumcheckProof,
}

impl fmt::Debug for ReadWriteMemoryProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        
        // 
        write!(
            f,
            r#"{{
            "memory_checking_proof": {:?},
            "timestamp_validity_proof": {:?},
            "output_proof": {:?}
            }}"#,
            self.memory_checking_proof, self.timestamp_validity_proof, self.output_proof
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstMemoryCheckingProofCircom{
    pub multiset_hashes: MultiSethashesCircom,
    pub read_write_grand_product: BatchedGrandProductProofCircom,
    pub init_final_grand_product: BatchedGrandProductProofCircom,
    pub openings: Vec<Fqq>
}

impl fmt::Debug for InstMemoryCheckingProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 
        //             ,
        // 
        // 
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

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampValidityProofCircom{
    pub multiset_hashes: MultiSethashesCircom,
    pub openings: TimestampRangeCheckOpenings,
    pub exogenous_openings: Vec<Fqq>,
    pub batched_grand_product: BatchedGrandProductProofCircom
}

impl fmt::Debug for TimestampValidityProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ,
        //     
        write!(
            f,
            r#"{{
            "multiset_hashes": {:?},
            "openings": {:?},
            "exogenous_openings": {:?},
            "batched_grand_product": {:?}
            }}"#,
            self.multiset_hashes, self.openings, self.exogenous_openings
            , self.batched_grand_product
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampRangeCheckOpenings{
    read_cts_read_timestamp: Vec<Fqq>,
    read_cts_global_minus_read: Vec<Fqq>,
    final_cts_read_timestamp: Vec<Fqq>,
    final_cts_global_minus_read: Vec<Fqq>,
    identity: Fqq
}

impl fmt::Debug for TimestampRangeCheckOpenings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "read_cts_read_timestamp": {:?},
            "read_cts_global_minus_read": {:?},
            "final_cts_read_timestamp": {:?},
            "final_cts_global_minus_read": {:?},
            "identity": {:?}
            }}"#,
            self.read_cts_read_timestamp, self.read_cts_global_minus_read, self.final_cts_read_timestamp, self.final_cts_global_minus_read, self.identity
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputSumcheckProof{
    sumcheck_proof: SumcheckInstanceProofCircom,
    opening: Fqq
}

impl fmt::Debug for OutputSumcheckProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "sumcheck_proof": {:?},
            "opening": {:?}
            }}"#,
            self.sumcheck_proof, self.opening
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrimarySumcheckOpeningsCircom{
    pub E_poly_openings: Vec<Fqq>,
    pub flag_openings: Vec<Fqq>,
    pub lookup_outputs_opening: Fqq
}

impl fmt::Debug for PrimarySumcheckOpeningsCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "E_poly_openings": {:?},
            "flag_openings": {:?},
            "lookup_outputs_opening": {:?}
            }}"#,
            self.E_poly_openings, self.flag_openings, self.lookup_outputs_opening
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrimarySumcheckCircom{
    pub sumcheck_proof: SumcheckInstanceProofCircom,
    pub openings: PrimarySumcheckOpeningsCircom
}

impl fmt::Debug for PrimarySumcheckCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "sumcheck_proof": {:?},
            "openings": {:?}
            }}"#,
            self.sumcheck_proof, self.openings
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstructionLookupsProofCircom{
    pub primary_sumcheck: PrimarySumcheckCircom,
    pub memory_checking: InstMemoryCheckingProofCircom
}

impl fmt::Debug for InstructionLookupsProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ,
        // 
        write!(
            f,
            r#"{{
            "primary_sumcheck": {:?},
            "memory_checking_proof": {:?}
            }}"#,
            self.primary_sumcheck, self.memory_checking
        )
    }
}

pub fn convert_from_read_write_mem_proof_to_circom(rw_mem_proof: ReadWriteMemoryProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>) -> ReadWriteMemoryProofCircom
{
    let mut openings = Vec::new();
    // confirm the 9 required values
    let rw_openings = rw_mem_proof.memory_checking_proof.openings;
    
    openings.push(
        Fqq{
            element: rw_openings.a_ram,
            limbs: convert_to_3_limbs(rw_openings.a_ram),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_read_rd,
            limbs: convert_to_3_limbs(rw_openings.v_read_rd),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_read_rs1,
            limbs: convert_to_3_limbs(rw_openings.v_read_rs1),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_read_rs2,
            limbs: convert_to_3_limbs(rw_openings.v_read_rs2),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_read_ram,
            limbs: convert_to_3_limbs(rw_openings.v_read_ram),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_write_rd,
            limbs: convert_to_3_limbs(rw_openings.v_write_rd),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_write_ram,
            limbs: convert_to_3_limbs(rw_openings.v_write_ram),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.v_final,
            limbs: convert_to_3_limbs(rw_openings.v_final),
        }
    );
    openings.push( 
        Fqq{
            element: rw_openings.t_read_rd,
            limbs: convert_to_3_limbs(rw_openings.t_read_rd),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.t_read_rs1,
            limbs: convert_to_3_limbs(rw_openings.t_read_rs1),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.t_read_rs2,
            limbs: convert_to_3_limbs(rw_openings.t_read_rs2),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.t_read_ram,
            limbs: convert_to_3_limbs(rw_openings.t_read_ram),
        }
    );
    openings.push(
        Fqq{
            element: rw_openings.t_final,
            limbs: convert_to_3_limbs(rw_openings.t_final),
            }
    );
    for i in 0..3{
        openings.push(
            Fqq{
                element: Scalar::from(0u8),
                limbs: [Fp::from(0u8); 3],
                }
        );
    }

    // println!("openings.len() is {}", openings.len());

    let exogenous_openings_from_rust = rw_mem_proof.memory_checking_proof.exogenous_openings;
    let mut exogenous_openings = Vec::new();
    exogenous_openings.push(
        Fqq{
            element: exogenous_openings_from_rust.a_rd,
            limbs: convert_to_3_limbs(exogenous_openings_from_rust.a_rd),
        }
    );
    exogenous_openings.push(
        Fqq{
            element: exogenous_openings_from_rust.a_rs1,
            limbs: convert_to_3_limbs(exogenous_openings_from_rust.a_rs1),
        }
    );
    exogenous_openings.push(
        Fqq{
            element: exogenous_openings_from_rust.a_rs2,
            limbs: convert_to_3_limbs(exogenous_openings_from_rust.a_rs2),
        }
    );
    // println!("exogenous_openings.len() is {}", exogenous_openings.len());


    let mem_checking_proof = ReadWriteMemoryCheckingProofCircom {
        multiset_hashes: convert_multiset_hashes_to_circom(&rw_mem_proof.memory_checking_proof.multiset_hashes),
        read_write_grand_product: convert_from_batched_GKRProof_to_circom(&rw_mem_proof.memory_checking_proof.read_write_grand_product),
        init_final_grand_product: convert_from_batched_GKRProof_to_circom(&rw_mem_proof.memory_checking_proof.init_final_grand_product),
        openings,
        exogenous_openings,
    };


    let ts_openings = rw_mem_proof.timestamp_validity_proof.openings;
    let mut openings = Vec::new();
    for opening in ts_openings.read_write_values() {
        openings.push(Fqq {
            element: opening.clone(),
            limbs: convert_to_3_limbs(opening.clone()),
        });
    }
    
    let ts_exo_openings = rw_mem_proof.timestamp_validity_proof.exogenous_openings;
    let mut exo_openings: Vec<Fqq> = Vec::new();
    for opening in ts_exo_openings {
        exo_openings.push(Fqq {
            element: opening.clone(),
            limbs: convert_to_3_limbs(opening.clone()),
        });
    }

    
    let ts_validity_proof = TimestampValidityProofCircom{
        multiset_hashes: convert_multiset_hashes_to_circom(&rw_mem_proof.timestamp_validity_proof.multiset_hashes),
        openings: TimestampRangeCheckOpenings{
            read_cts_read_timestamp: openings[0..MEMORY_OPS_PER_INSTRUCTION].to_vec(),
            read_cts_global_minus_read: openings[MEMORY_OPS_PER_INSTRUCTION..2 * MEMORY_OPS_PER_INSTRUCTION].to_vec(),
            final_cts_read_timestamp: openings[2 * MEMORY_OPS_PER_INSTRUCTION..3 * MEMORY_OPS_PER_INSTRUCTION].to_vec(),
            final_cts_global_minus_read: openings[3 * MEMORY_OPS_PER_INSTRUCTION..4 * MEMORY_OPS_PER_INSTRUCTION].to_vec(),
            identity: Fqq{
                element: Scalar::from(0u8),
                limbs: [Fp::from(0u8); 3],
            },
        },
        exogenous_openings: exo_openings,
        batched_grand_product: convert_from_batched_GKRProof_to_circom(&rw_mem_proof.timestamp_validity_proof.batched_grand_product),
    };

    let ouput_sum_check_proof: OutputSumcheckProof = OutputSumcheckProof{
        sumcheck_proof: convert_sum_check_proof_to_circom(&rw_mem_proof.output_proof.sumcheck_proof),
        opening: Fqq { element: rw_mem_proof.output_proof.opening, limbs: convert_to_3_limbs(rw_mem_proof.output_proof.opening) },
    };

    ReadWriteMemoryProofCircom{
        memory_checking_proof: mem_checking_proof,
        timestamp_validity_proof: ts_validity_proof,
        output_proof: ouput_sum_check_proof,
    }
}

const MEMORY_OPS_PER_INSTRUCTION: usize = 4;


pub fn convert_from_inst_lookups_proof_to_circom(inst_lookup_proof: InstructionLookupsProof<{C}, {M}, Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, RV32I, RV32ISubtables<Scalar> ,PoseidonTranscript<Fp>>) -> InstructionLookupsProofCircom{
    let primary_sum_check = PrimarySumcheckCircom{
        sumcheck_proof: convert_sum_check_proof_to_circom(&inst_lookup_proof.primary_sumcheck.sumcheck_proof),
        openings: convert_from_primary_sum_check_opening_to_circom(&inst_lookup_proof.primary_sumcheck.openings),
    };

    let mut openings = Vec::new();
    let lookup_openings = inst_lookup_proof.memory_checking.openings;
    // for opening in lookup_openings.read_write_values() {
    //     openings.push(Fqq {
    //         element: opening.clone(),
    //         limbs: convert_to_3_limbs(opening.clone()),
    //     });
    // }
    // pub(crate) dim: Vec<T>,
    // /// `num_memories`-sized vector of polynomials/commitments/openings corresponding to
    // /// the read access counts for each memory.
    // pub read_cts: Vec<T>,
    // /// `num_memories`-sized vector of polynomials/commitments/openings corresponding to
    // /// the final access counts for each memory.
    // pub(crate) final_cts: Vec<T>,
    // /// `num_memories`-sized vector of polynomials/commitments/openings corresponding to
    // /// the values read from each memory.
    // pub(crate) E_polys: Vec<T>,
    // /// `NUM_INSTRUCTIONS`-sized vector of polynomials/commitments/openings corresponding
    // /// to the indicator bitvectors designating which lookup to perform at each step of
    // /// the execution trace.
    // pub(crate) instruction_flags: Vec<T>,
    // /// The polynomial/commitment/opening corresponding to the lookup output for each
    // /// step of the execution trace.
    // pub(crate) lookup_outputs: T,
    for i in 0..lookup_openings.dim.len(){
        openings.push(
            Fqq{
                element: lookup_openings.dim[i],
                limbs: convert_to_3_limbs(lookup_openings.dim[i]),
            }
        );
    }
    for i in 0..lookup_openings.read_cts.len(){
        openings.push(
            Fqq{
                element: lookup_openings.read_cts[i],
                limbs: convert_to_3_limbs(lookup_openings.read_cts[i])
            }
        )
    };
    for i in 0..lookup_openings.final_cts.len(){
        openings.push(
            Fqq{
                element: lookup_openings.final_cts[i],
                limbs: convert_to_3_limbs(lookup_openings.final_cts[i])
            }
        )
    };
    for i in 0..lookup_openings.E_polys.len(){
        openings.push(
            Fqq{
                element: lookup_openings.E_polys[i],
                limbs: convert_to_3_limbs(lookup_openings.E_polys[i])
            }
        )
    };
    for i in 0..lookup_openings.instruction_flags.len(){
        openings.push(
            Fqq{
                element: lookup_openings.instruction_flags[i],
                limbs: convert_to_3_limbs(lookup_openings.instruction_flags[i])
            }
        )
    };
    openings.push(
        Fqq{
            element: lookup_openings.lookup_outputs,
            limbs: convert_to_3_limbs(lookup_openings.lookup_outputs)
        }
    );
    // println!("openings.len() is {}", openings.len());
    

    let mem_checking_proof = InstMemoryCheckingProofCircom{
        multiset_hashes: convert_multiset_hashes_to_circom(&inst_lookup_proof.memory_checking.multiset_hashes),
        read_write_grand_product: convert_from_batched_GKRProof_to_circom(&inst_lookup_proof.memory_checking.read_write_grand_product),
        init_final_grand_product: convert_from_batched_GKRProof_to_circom(&inst_lookup_proof.memory_checking.init_final_grand_product),
        openings: openings,
    };

    InstructionLookupsProofCircom{
        primary_sumcheck: primary_sum_check,
        memory_checking: mem_checking_proof,
    }
}

pub fn convert_from_primary_sum_check_opening_to_circom(prim_s_c_openings: &PrimarySumcheckOpenings<Scalar>) -> PrimarySumcheckOpeningsCircom{
    let mut E_poly_openings = Vec::new();
    for i in 0..prim_s_c_openings.E_poly_openings.len(){
        E_poly_openings.push(
            Fqq{
                element: prim_s_c_openings.E_poly_openings[i],
                limbs: convert_to_3_limbs(prim_s_c_openings.E_poly_openings[i]),
            }
        )
    }
    let mut flag_openings = Vec::new();
    for i in 0..prim_s_c_openings.flag_openings.len(){
        flag_openings.push(
            Fqq{
                element: prim_s_c_openings.flag_openings[i],
                limbs: convert_to_3_limbs(prim_s_c_openings.flag_openings[i]),
            }
        );
    }
    


    PrimarySumcheckOpeningsCircom{
        E_poly_openings,
        flag_openings,
        lookup_outputs_opening: Fqq{
            element: prim_s_c_openings.lookup_outputs_opening,
            limbs: convert_to_3_limbs(prim_s_c_openings.lookup_outputs_opening)
        }

    }

}

pub fn convert_reduced_opening_proof_to_circom(red_opening: ReducedOpeningProof<Scalar, HyperKZG<Bn254, PoseidonTranscript<Fp>>, PoseidonTranscript<Fp>>) -> ReducedOpeningProofCircom{
    let mut claims = Vec::new();
    // println!("red_opening.sumcheck_claims.len() is {}", red_opening.sumcheck_claims.len());
    for i in 0..red_opening.sumcheck_claims.len(){
        claims.push(
            Fqq{
                element: red_opening.sumcheck_claims[i],
                limbs: convert_to_3_limbs(red_opening.sumcheck_claims[i]),
            }
        )
    }
    ReducedOpeningProofCircom{
        sumcheck_proof: convert_sum_check_proof_to_circom(&red_opening.sumcheck_proof),
        sumcheck_claims: claims,
        joint_opening_proof: hyper_kzg_proof_to_hyper_kzg_circom(red_opening.joint_opening_proof),
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadWriteMemoryCheckingProofCircom{
    pub multiset_hashes: MultiSethashesCircom,
    pub read_write_grand_product: BatchedGrandProductProofCircom,
    pub init_final_grand_product: BatchedGrandProductProofCircom,
    pub openings: Vec<Fqq>,
    pub exogenous_openings: Vec<Fqq>
}
impl fmt::Debug for ReadWriteMemoryCheckingProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //             
        write!(
            f,
            r#"{{
            "multiset_hashes": {:?},
            "read_write_grand_product": {:?},
            "init_final_grand_product": {:?},
            "openings": {:?},
            "exogenous_openings": {:?}
            }}"#,
            self.multiset_hashes, self.read_write_grand_product, self.init_final_grand_product,self.openings
            , self.exogenous_openings,
        )
    }
}



