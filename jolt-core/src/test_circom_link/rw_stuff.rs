use core::fmt;

use ark_bn254::Bn254;

use crate::{jolt::vm::read_write_memory::ReadWriteMemoryStuff, poly::commitment::hyperkzg::HyperKZGCommitment};

use super::link_joltstuff::{convert_hyperkzg_commitment_to_circom, HyperKZGCommitmentCircomLink};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadWriteMemoryStuffCircomLink{
    pub a_ram: HyperKZGCommitmentCircomLink,
    /// RD read_value
    pub v_read_rd: HyperKZGCommitmentCircomLink,
    /// RS1 read_value
    pub v_read_rs1: HyperKZGCommitmentCircomLink,
    /// RS2 read_value
    pub v_read_rs2: HyperKZGCommitmentCircomLink,
    /// RAM read_value
    pub v_read_ram: HyperKZGCommitmentCircomLink,
    /// RD write value
    pub v_write_rd: HyperKZGCommitmentCircomLink,
    /// RAM write value
    pub v_write_ram: HyperKZGCommitmentCircomLink,
    /// Final memory state.
    pub v_final: HyperKZGCommitmentCircomLink,
    /// RD read timestamp
    pub t_read_rd: HyperKZGCommitmentCircomLink,
    /// RS1 read timestamp
    pub t_read_rs1: HyperKZGCommitmentCircomLink,
    /// RS2 read timestamp
    pub t_read_rs2: HyperKZGCommitmentCircomLink,
    /// RAM read timestamp
    pub t_read_ram: HyperKZGCommitmentCircomLink,
    /// Final timestamps.
    pub t_final: HyperKZGCommitmentCircomLink,
}

impl fmt::Debug for ReadWriteMemoryStuffCircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "a_ram": {:?},
                "v_read_rd": {:?},
                "v_read_rs1": {:?},
                "v_read_rs2": {:?},
                "v_read_ram": {:?},
                "v_write_rd": {:?},
                "v_write_ram": {:?},
                "v_final": {:?},
                "t_read_rd": {:?},
                "t_read_rs1": {:?},
                "t_read_rs2": {:?},
                "t_read_ram": {:?},
                "t_final": {:?}
            }}"#,
            self.a_ram, self.v_read_rd, self.v_read_rs1, self.v_read_rs2, self.v_read_ram, self.v_write_rd, self.v_write_ram, self.v_final, self.t_read_rd, self.t_read_rs1, self.t_read_rs2, self.t_read_ram, self.t_final
        )
    }
}


pub fn convert_from_read_write_mem_stuff_to_circom(rw_stuff: &ReadWriteMemoryStuff<HyperKZGCommitment<Bn254>>) -> ReadWriteMemoryStuffCircomLink{

    ReadWriteMemoryStuffCircomLink{
        a_ram: convert_hyperkzg_commitment_to_circom(&rw_stuff.a_ram),
        v_read_rd: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_read_rd),
        v_read_rs1: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_read_rs1),
        v_read_rs2: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_read_rs2),
        v_read_ram: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_read_ram),
        v_write_rd: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_write_rd),
        v_write_ram: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_write_ram),
        v_final: convert_hyperkzg_commitment_to_circom(&rw_stuff.v_final),
        t_read_rd: convert_hyperkzg_commitment_to_circom(&rw_stuff.t_read_rd),
        t_read_rs1: convert_hyperkzg_commitment_to_circom(&rw_stuff.t_read_rs1),
        t_read_rs2: convert_hyperkzg_commitment_to_circom(&rw_stuff.t_read_rs2),
        t_read_ram: convert_hyperkzg_commitment_to_circom(&rw_stuff.t_read_ram),
        t_final: convert_hyperkzg_commitment_to_circom(&rw_stuff.t_final)
    }
}