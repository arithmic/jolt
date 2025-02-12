use core::fmt;

use ark_bn254::Bn254;

use crate::{jolt::vm::bytecode::BytecodeStuff, poly::commitment::hyperkzg::HyperKZGCommitment};

use super::link_joltstuff::{convert_hyperkzg_commitment_to_circom, HyperKZGCommitmentCircomLink};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteCodeStuffCircomLink{
    pub a_read_write: HyperKZGCommitmentCircomLink,
    pub v_read_write: Vec<HyperKZGCommitmentCircomLink>,
    pub t_read: HyperKZGCommitmentCircomLink,
    pub t_final: HyperKZGCommitmentCircomLink,

}

impl fmt::Debug for ByteCodeStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "a_read_write": {:?},
                "v_read_write": {:?},
                "t_read": {:?},
                "t_final": {:?}
            }}"#,
            self.a_read_write, self.v_read_write, self.t_read, self.t_final
        )
    }
}

pub fn convert_from_byte_code_stuff_to_circom(byte_code_stuff: &BytecodeStuff<HyperKZGCommitment<Bn254>>) -> ByteCodeStuffCircomLink{
    let mut v_read_write = Vec::new();
    for i in 0..byte_code_stuff.v_read_write.len(){
        v_read_write.push(convert_hyperkzg_commitment_to_circom(&byte_code_stuff.v_read_write[i].clone()))
    }
    ByteCodeStuffCircomLink{
        a_read_write: convert_hyperkzg_commitment_to_circom(&byte_code_stuff.a_read_write),
        v_read_write: v_read_write,
        t_read: convert_hyperkzg_commitment_to_circom(&byte_code_stuff.t_read),
        t_final: convert_hyperkzg_commitment_to_circom(&byte_code_stuff.t_final)
    }
}