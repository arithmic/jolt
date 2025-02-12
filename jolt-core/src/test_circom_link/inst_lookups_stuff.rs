use core::fmt;

use ark_bn254::Bn254;

use crate::{jolt::vm::instruction_lookups::InstructionLookupStuff, poly::commitment::hyperkzg::HyperKZGCommitment};

use super::link_joltstuff::{convert_hyperkzg_commitment_to_circom, HyperKZGCommitmentCircomLink};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstructionLookupStuffCircomLink{
    pub dim: Vec<HyperKZGCommitmentCircomLink>,
    pub read_cts: Vec<HyperKZGCommitmentCircomLink>,
    pub final_cts: Vec<HyperKZGCommitmentCircomLink>,
    pub E_polys: Vec<HyperKZGCommitmentCircomLink>,
    pub instruction_flags: Vec<HyperKZGCommitmentCircomLink>,
    pub lookup_outputs: HyperKZGCommitmentCircomLink,
    // instruction_flag_bitvectors commented
}

impl fmt::Debug for InstructionLookupStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "dim": {:?},
                "read_cts": {:?},
                "final_cts": {:?},
                "E_polys": {:?},
                "instruction_flags": {:?},
                "lookup_outputs": {:?}
            }}"#,
            self.dim, self.read_cts, self.final_cts, self.E_polys, self.instruction_flags, self.lookup_outputs
        )
    }
}

pub fn convert_from_ins_lookup_stuff_to_circom(ins_lookup_stuff: &InstructionLookupStuff<HyperKZGCommitment<Bn254>>) -> InstructionLookupStuffCircomLink{
    let mut dim = Vec::new();
    let mut read_cts = Vec::new();
    let mut final_cts = Vec::new();
    let mut E_polys = Vec::new();
    let mut instruction_flags = Vec::new();
    for i in 0..ins_lookup_stuff.dim.len(){
        dim.push(convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.dim[i].clone()));
    }
    for i in 0..ins_lookup_stuff.read_cts.len(){
        read_cts.push(convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.read_cts[i].clone()));
    }
    for i in 0..ins_lookup_stuff.final_cts.len(){
        final_cts.push(convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.final_cts[i].clone()))
    }
    for i in 0..ins_lookup_stuff.E_polys.len(){
        E_polys.push(convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.E_polys[i].clone()));
    }
    for i in 0..ins_lookup_stuff.instruction_flags.len(){
        instruction_flags.push(convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.instruction_flags[i].clone()));
    }

    InstructionLookupStuffCircomLink{
        dim,
        read_cts,
        final_cts,
        E_polys,
        instruction_flags,
        lookup_outputs: convert_hyperkzg_commitment_to_circom(&ins_lookup_stuff.lookup_outputs)
    }
}
