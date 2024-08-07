use std::str::FromStr;

use crate::constants::{
    BYTES_PER_INSTRUCTION, MEMORY_OPS_PER_INSTRUCTION, RAM_START_ADDRESS, REGISTER_COUNT,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use strum_macros::FromRepr;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RVTraceRow {
    pub instruction: ELFInstruction,
    pub register_state: RegisterState,
    pub memory_state: Option<MemoryState>,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum MemoryOp {
    Read(u64),       // (address)
    Write(u64, u64), // (address, new_value)
}

impl MemoryOp {
    pub fn noop_read() -> Self {
        Self::Read(0)
    }

    pub fn noop_write() -> Self {
        Self::Write(0, 0)
    }
}

fn sum_u64_i32(a: u64, b: i32) -> u64 {
    if b.is_negative() {
        let abs_b = b.unsigned_abs() as u64;
        if a < abs_b {
            panic!("overflow")
        }
        a - abs_b
    } else {
        let b_u64: u64 = b.try_into().expect("failed u64 convesion");
        a + b_u64
    }
}

impl From<&RVTraceRow> for ([MemoryOp; MEMORY_OPS_PER_INSTRUCTION], (u64, u64)) {
    fn from(val: &RVTraceRow) -> Self {
        let instruction_type = val.instruction.opcode.instruction_type();

        let rs1_read = || MemoryOp::Read(val.instruction.rs1.unwrap());
        let rs2_read = || MemoryOp::Read(val.instruction.rs2.unwrap());
        let rd_write = || {
            MemoryOp::Write(
                val.instruction.rd.unwrap(),
                val.register_state.rd_post_val.unwrap(),
            )
        };

        let ram_byte_written = |index: usize| match val.memory_state {
            Some(MemoryState::Read {
                address: _,
                value: _,
            }) => panic!("Unexpected MemoryState::Read"),
            Some(MemoryState::Write {
                address: _,
                post_value,
            }) => (post_value >> (index * 8)) as u8,
            None => panic!("Memory state not found"),
        };

        let rs1_offset = || -> u64 {
            let rs1_val = val.register_state.rs1_val.unwrap();
            let imm = val.instruction.imm.unwrap();
            sum_u64_i32(rs1_val, imm as i32)
        };

        // Canonical ordering for memory instructions
        // 0: rs1
        // 1: rs2
        // 2: rd
        // 3: byte_0
        // 4: byte_1
        // 5: byte_2
        // 6: byte_3
        // If any are empty a no_op is inserted.

        // Validation: Number of ops should be a multiple of 7
        match instruction_type {
            RV32InstructionFormat::R => (
                [
                    rs1_read(),
                    rs2_read(),
                    rd_write(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                ],
                (0, 0),
            ),
            RV32InstructionFormat::U => (
                [
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    rd_write(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                ],
                (0, 0),
            ),
            RV32InstructionFormat::I => match val.instruction.opcode {
                RV32IM::ADDI
                | RV32IM::SLLI
                | RV32IM::SRLI
                | RV32IM::SRAI
                | RV32IM::ANDI
                | RV32IM::ORI
                | RV32IM::XORI
                | RV32IM::SLTI
                | RV32IM::SLTIU
                | RV32IM::JALR
                | RV32IM::VIRTUAL_MOVSIGN => (
                    [
                        rs1_read(),
                        MemoryOp::noop_read(),
                        rd_write(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                    ],
                    (0, 0),
                ),
                RV32IM::LB | RV32IM::LBU => match rs1_offset() % (BYTES_PER_INSTRUCTION as u64) {
                    0 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset()),
                            MemoryOp::Read(rs1_offset() + 1),
                            MemoryOp::Read(rs1_offset() + 2),
                            MemoryOp::Read(rs1_offset() + 3),
                        ],
                        (0, 0),
                    ),
                    1 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Read(rs1_offset()),
                            MemoryOp::Read(rs1_offset() + 1),
                            MemoryOp::Read(rs1_offset() + 2),
                        ],
                        (1, 0),
                    ),
                    2 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Read(rs1_offset()),
                            MemoryOp::Read(rs1_offset() + 1),
                        ],
                        (0, 1),
                    ),
                    3 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset() - 3),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Read(rs1_offset()),
                        ],
                        (1, 1),
                    ),
                    _ => {
                        panic!("Invalid Remainder!");
                    }
                },
                RV32IM::LH | RV32IM::LHU => match rs1_offset() % (BYTES_PER_INSTRUCTION as u64) {
                    0 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset()),
                            MemoryOp::Read(rs1_offset() + 1),
                            MemoryOp::Read(rs1_offset() + 2),
                            MemoryOp::Read(rs1_offset() + 3),
                        ],
                        (0, 0),
                    ),
                    2 => (
                        [
                            rs1_read(),
                            MemoryOp::noop_read(),
                            rd_write(),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Read(rs1_offset()),
                            MemoryOp::Read(rs1_offset() + 1),
                        ],
                        (0, 1),
                    ),
                    _ => {
                        panic!("Invalid Remainder!");
                    }
                },
                RV32IM::LW => (
                    [
                        rs1_read(),
                        MemoryOp::noop_read(),
                        rd_write(),
                        MemoryOp::Read(rs1_offset()),
                        MemoryOp::Read(rs1_offset() + 1),
                        MemoryOp::Read(rs1_offset() + 2),
                        MemoryOp::Read(rs1_offset() + 3),
                    ],
                    (0, 0),
                ),
                RV32IM::FENCE => (
                    [
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_write(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                        MemoryOp::noop_read(),
                    ],
                    (0, 0),
                ),
                _ => unreachable!("{val:?}"),
            },
            RV32InstructionFormat::S => match val.instruction.opcode {
                RV32IM::SB => match rs1_offset() % (BYTES_PER_INSTRUCTION as u64) {
                    0 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                            MemoryOp::Read(rs1_offset() + 1),
                            MemoryOp::Read(rs1_offset() + 2),
                            MemoryOp::Read(rs1_offset() + 3),
                        ],
                        (0, 0),
                    ),
                    1 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                            MemoryOp::Read(rs1_offset() + 1),
                            MemoryOp::Read(rs1_offset() + 2),
                        ],
                        (1, 0),
                    ),
                    2 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                            MemoryOp::Read(rs1_offset() + 1),
                        ],
                        (0, 1),
                    ),
                    3 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Read(rs1_offset() - 3),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                        ],
                        (1, 1),
                    ),
                    _ => {
                        panic!("Invalid Remainder!");
                    }
                },
                RV32IM::SH => match rs1_offset() % (BYTES_PER_INSTRUCTION as u64) {
                    0 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                            MemoryOp::Write(rs1_offset() + 1, ram_byte_written(1) as u64),
                            MemoryOp::Read(rs1_offset() + 2),
                            MemoryOp::Read(rs1_offset() + 3),
                        ],
                        (0, 0),
                    ),
                    2 => (
                        [
                            rs1_read(),
                            rs2_read(),
                            MemoryOp::noop_write(),
                            MemoryOp::Read(rs1_offset() - 2),
                            MemoryOp::Read(rs1_offset() - 1),
                            MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                            MemoryOp::Write(rs1_offset() + 1, ram_byte_written(1) as u64),
                        ],
                        (0, 1),
                    ),
                    _ => {
                        panic!("Invalid Remainder!");
                    }
                },
                RV32IM::SW => (
                    [
                        rs1_read(),
                        rs2_read(),
                        MemoryOp::noop_write(),
                        MemoryOp::Write(rs1_offset(), ram_byte_written(0) as u64),
                        MemoryOp::Write(rs1_offset() + 1, ram_byte_written(1) as u64),
                        MemoryOp::Write(rs1_offset() + 2, ram_byte_written(2) as u64),
                        MemoryOp::Write(rs1_offset() + 3, ram_byte_written(3) as u64),
                    ],
                    (0, 0),
                ),
                _ => unreachable!(),
            },
            RV32InstructionFormat::UJ => (
                [
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    rd_write(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                ],
                (0, 0),
            ),
            RV32InstructionFormat::SB => (
                [
                    rs1_read(),
                    rs2_read(),
                    MemoryOp::noop_write(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                    MemoryOp::noop_read(),
                ],
                (0, 0),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ELFInstruction {
    pub address: u64,
    pub opcode: RV32IM,
    pub rs1: Option<u64>,
    pub rs2: Option<u64>,
    pub rd: Option<u64>,
    pub imm: Option<u32>,
    /// If this instruction is part of a "virtual sequence" (see Section 6.2 of the
    /// Jolt paper), then this contains the instruction's index within the sequence.
    pub virtual_sequence_index: Option<usize>,
}

pub const NUM_CIRCUIT_FLAGS: usize = 17;

impl ELFInstruction {
    #[rustfmt::skip]
    pub fn to_circuit_flags(&self) -> [bool; NUM_CIRCUIT_FLAGS] {
        // Jolt Appendix A.1
        // 0: first_operand == rs1 (1 if PC)
        // 1: second_operand == rs2 (1 if imm)
        // 2: LBU
        // 3: LHU
        // 4: LW
        // 5: LB
        // 6: LH
        // 7: SB
        // 8: SH
        // 9: SW
        // 5: Jump instruction
        // 6: Branch instruction
        // 7: Instruction writes lookup output to rd
        // 8: Sign-bit of imm
        // 9: Is concat
        // 10: Increment virtual PC
        // 11: Assert instruction

        let mut flags = [false; NUM_CIRCUIT_FLAGS];

        flags[0] = matches!(
            self.opcode,
            RV32IM::JAL | RV32IM::LUI | RV32IM::AUIPC,
        );

        flags[1] = matches!(
            self.opcode,
            RV32IM::ADDI
            | RV32IM::XORI
            | RV32IM::ORI
            | RV32IM::ANDI
            | RV32IM::SLLI
            | RV32IM::SRLI
            | RV32IM::SRAI
            | RV32IM::SLTI
            | RV32IM::SLTIU
            | RV32IM::AUIPC
            | RV32IM::JAL
            | RV32IM::JALR,
        );

        flags[2] = matches!(
            self.opcode,
            RV32IM::LBU,
        );

        flags[3] = matches!(
            self.opcode,
            RV32IM::LHU,
        );

        flags[4] = matches!(
            self.opcode,
            RV32IM::LW,
        );

        flags[5] = matches!(
            self.opcode,
            RV32IM::LB,
        );

        flags[6] = matches!(
            self.opcode,
            RV32IM::LH
        );

        flags[7] = matches!(
            self.opcode,
            RV32IM::SB
        );

        flags[8] = matches!(
            self.opcode,
            RV32IM::SH
        );

        flags[9] = matches!(
            self.opcode,
            RV32IM::SW
        );

        flags[10] = matches!(
            self.opcode,
            RV32IM::JAL | RV32IM::JALR,
        );

        flags[11] = matches!(
            self.opcode,
            RV32IM::BEQ | RV32IM::BNE | RV32IM::BLT | RV32IM::BGE | RV32IM::BLTU | RV32IM::BGEU,
        );

        // loads, stores, branches, jumps do not store the lookup output to rd (they may update rd in other ways)
        flags[12] = !matches!(
            self.opcode,
            RV32IM::SB
            | RV32IM::SH
            | RV32IM::SW
            | RV32IM::BEQ
            | RV32IM::BNE
            | RV32IM::BLT
            | RV32IM::BGE
            | RV32IM::BLTU
            | RV32IM::BGEU
            | RV32IM::JAL
            | RV32IM::JALR
            | RV32IM::LUI,
        );

        let mask = 1u32 << 31;
        flags[13] = matches!(self.imm, Some(imm) if imm & mask == mask);

        flags[14] = matches!(
            self.opcode,
            RV32IM::XOR
            | RV32IM::XORI
            | RV32IM::OR
            | RV32IM::ORI
            | RV32IM::AND
            | RV32IM::ANDI
            | RV32IM::SLL
            | RV32IM::SRL
            | RV32IM::SRA
            | RV32IM::SLLI
            | RV32IM::SRLI
            | RV32IM::SRAI
            | RV32IM::SLT
            | RV32IM::SLTU
            | RV32IM::SLTI
            | RV32IM::SLTIU
            | RV32IM::BEQ
            | RV32IM::BNE
            | RV32IM::BLT
            | RV32IM::BGE
            | RV32IM::BLTU
            | RV32IM::BGEU,
        );

        // TODO(moodlezoup): Use these flags in R1CS constraints
        flags[15] = match self.virtual_sequence_index {
            // For virtual sequences, we set
            //     virtual PC := ProgARW     (the bytecode `a` value)
            // if it's the first instruction in the sequence.
            // Otherwise, we increment the virtual PC:
            //     virtual PC += 1
            // This prevents a malicious prover from reordering or omitting
            // instructions from the virtual sequence.
            Some(i) => i > 0,
            // For "real" instructions, we always set
            //     virtual PC := ProgARW     (the bytecode `a` value)
            None => false
        };
        flags[16] = matches!(self.opcode,
            RV32IM::VIRTUAL_ASSERT_EQ     |
            RV32IM::VIRTUAL_ASSERT_LTE    |
            RV32IM::VIRTUAL_ASSERT_LTU    |
            RV32IM::VIRTUAL_ASSERT_LT_ABS |
            RV32IM::VIRTUAL_ASSERT_EQ_SIGNS,
        );

        flags
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisterState {
    pub rs1_val: Option<u64>,
    pub rs2_val: Option<u64>,
    pub rd_post_val: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MemoryState {
    Read { address: u64, value: u64 },
    Write { address: u64, post_value: u64 },
}

impl RVTraceRow {
    pub fn imm_u64(&self) -> u64 {
        match self.instruction.opcode.instruction_type() {
            RV32InstructionFormat::R => unimplemented!("R type does not use imm u64"),
            RV32InstructionFormat::I => self.instruction.imm.unwrap() as u64,
            RV32InstructionFormat::U => self.instruction.imm.unwrap() as u64,
            RV32InstructionFormat::S => unimplemented!("S type does not use imm u64"),
            // UJ-type instructions point to address offsets: even numbers.
            // TODO(JOLT-88): De-normalizing was already done elsewhere. Should make this is consistent.
            RV32InstructionFormat::UJ => self.instruction.imm.unwrap() as u64,
            _ => unimplemented!(),
        }
    }
}

// Reference: https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromRepr, Serialize, Deserialize, Hash)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum RV32IM {
    ADD,
    SUB,
    XOR,
    OR,
    AND,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,
    ADDI,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    SLTI,
    SLTIU,
    LB,
    LH,
    LW,
    LBU,
    LHU,
    SB,
    SH,
    SW,
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    JAL,
    JALR,
    LUI,
    AUIPC,
    ECALL,
    EBREAK,
    MUL,
    MULH,
    MULHU,
    MULHSU,
    MULU,
    DIV,
    DIVU,
    REM,
    REMU,
    FENCE,
    UNIMPL,
    // Virtual instructions
    VIRTUAL_MOVSIGN,
    VIRTUAL_ADVICE,
    VIRTUAL_ASSERT_LTU,
    VIRTUAL_ASSERT_LTE,
    VIRTUAL_ASSERT_LT_ABS,
    VIRTUAL_ASSERT_EQ_SIGNS,
    VIRTUAL_ASSERT_EQ,
}

impl FromStr for RV32IM {
    type Err = String;

    fn from_str(s: &str) -> Result<RV32IM, String> {
        match s {
            "ADD" => Ok(Self::ADD),
            "SUB" => Ok(Self::SUB),
            "XOR" => Ok(Self::XOR),
            "OR" => Ok(Self::OR),
            "AND" => Ok(Self::AND),
            "SLL" => Ok(Self::SLL),
            "SRL" => Ok(Self::SRL),
            "SRA" => Ok(Self::SRA),
            "SLT" => Ok(Self::SLT),
            "SLTU" => Ok(Self::SLTU),
            "ADDI" => Ok(Self::ADDI),
            "XORI" => Ok(Self::XORI),
            "ORI" => Ok(Self::ORI),
            "ANDI" => Ok(Self::ANDI),
            "SLLI" => Ok(Self::SLLI),
            "SRLI" => Ok(Self::SRLI),
            "SRAI" => Ok(Self::SRAI),
            "SLTI" => Ok(Self::SLTI),
            "SLTIU" => Ok(Self::SLTIU),
            "LB" => Ok(Self::LB),
            "LH" => Ok(Self::LH),
            "LW" => Ok(Self::LW),
            "LBU" => Ok(Self::LBU),
            "LHU" => Ok(Self::LHU),
            "SB" => Ok(Self::SB),
            "SH" => Ok(Self::SH),
            "SW" => Ok(Self::SW),
            "BEQ" => Ok(Self::BEQ),
            "BNE" => Ok(Self::BNE),
            "BLT" => Ok(Self::BLT),
            "BGE" => Ok(Self::BGE),
            "BLTU" => Ok(Self::BLTU),
            "BGEU" => Ok(Self::BGEU),
            "JAL" => Ok(Self::JAL),
            "JALR" => Ok(Self::JALR),
            "LUI" => Ok(Self::LUI),
            "AUIPC" => Ok(Self::AUIPC),
            "ECALL" => Ok(Self::ECALL),
            "EBREAK" => Ok(Self::EBREAK),
            "MUL" => Ok(Self::MUL),
            "MULH" => Ok(Self::MULH),
            "MULHU" => Ok(Self::MULHU),
            "MULHSU" => Ok(Self::MULHSU),
            "MULU" => Ok(Self::MULU),
            "DIV" => Ok(Self::DIV),
            "DIVU" => Ok(Self::DIVU),
            "REM" => Ok(Self::REM),
            "REMU" => Ok(Self::REMU),
            "FENCE" => Ok(Self::FENCE),
            "UNIMPL" => Ok(Self::UNIMPL),
            _ => Err("Could not match instruction to RV32IM set.".to_string()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RV32InstructionFormat {
    R,
    I,
    S,
    SB,
    U,
    UJ,
}

impl RV32IM {
    #[rustfmt::skip] // keep matches pretty
    pub fn instruction_type(&self) -> RV32InstructionFormat {
        match self {
            RV32IM::ADD    |
            RV32IM::SUB    |
            RV32IM::XOR    |
            RV32IM::OR     |
            RV32IM::AND    |
            RV32IM::SLL    |
            RV32IM::SRL    |
            RV32IM::SRA    |
            RV32IM::SLT    |
            RV32IM::SLTU   |
            RV32IM::MUL    |
            RV32IM::MULH   |
            RV32IM::MULHU  |
            RV32IM::MULHSU |
            RV32IM::MULU   |
            RV32IM::DIV    |
            RV32IM::DIVU   |
            RV32IM::REM    |
            RV32IM::REMU => RV32InstructionFormat::R,

            RV32IM::ADDI  |
            RV32IM::XORI  |
            RV32IM::ORI   |
            RV32IM::ANDI  |
            RV32IM::SLLI  |
            RV32IM::SRLI  |
            RV32IM::SRAI  |
            RV32IM::SLTI  |
            RV32IM::FENCE |
            RV32IM::SLTIU |
            RV32IM::VIRTUAL_MOVSIGN=> RV32InstructionFormat::I,

            RV32IM::LB  |
            RV32IM::LH  |
            RV32IM::LW  |
            RV32IM::LBU |
            RV32IM::LHU |
            RV32IM::JALR => RV32InstructionFormat::I,

            RV32IM::SB |
            RV32IM::SH |
            RV32IM::SW => RV32InstructionFormat::S,

            RV32IM::BEQ  |
            RV32IM::BNE  |
            RV32IM::BLT  |
            RV32IM::BGE  |
            RV32IM::BLTU |
            RV32IM::BGEU |
            RV32IM::VIRTUAL_ASSERT_EQ     |
            RV32IM::VIRTUAL_ASSERT_LTE    |
            RV32IM::VIRTUAL_ASSERT_LTU    |
            RV32IM::VIRTUAL_ASSERT_LT_ABS |
            RV32IM::VIRTUAL_ASSERT_EQ_SIGNS => RV32InstructionFormat::SB,

            RV32IM::LUI   |
            RV32IM::AUIPC |
            RV32IM::VIRTUAL_ADVICE=> RV32InstructionFormat::U,

            RV32IM::JAL => RV32InstructionFormat::UJ,

            RV32IM::ECALL  |
            RV32IM::EBREAK |
            RV32IM::UNIMPL => unimplemented!(),
        }
    }
}

/// Represented as a "peripheral device" in the RISC-V emulator, this captures
/// all reads from the reserved memory address space for program inputs and all writes
/// to the reserved memory address space for program outputs.
/// The inputs and outputs are part of the public inputs to the proof.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct JoltDevice {
    pub inputs: Vec<u8>,
    pub outputs: Vec<u8>,
    pub panic: bool,
    pub memory_layout: MemoryLayout,
}

impl JoltDevice {
    pub fn new(max_input_size: u64, max_output_size: u64) -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            panic: false,
            memory_layout: MemoryLayout::new(max_input_size, max_output_size),
        }
    }

    pub fn load(&self, address: u64) -> u8 {
        let internal_address = self.convert_read_address(address);
        if self.inputs.len() <= internal_address {
            0
        } else {
            self.inputs[internal_address]
        }
    }

    pub fn store(&mut self, address: u64, value: u8) {
        if address == self.memory_layout.panic {
            println!("GUEST PANIC");
            self.panic = true;
            return;
        }

        let internal_address = self.convert_write_address(address);
        if self.outputs.len() <= internal_address {
            self.outputs.resize(internal_address + 1, 0);
        }

        self.outputs[internal_address] = value;
    }

    pub fn size(&self) -> usize {
        self.inputs.len() + self.outputs.len()
    }

    pub fn is_input(&self, address: u64) -> bool {
        address >= self.memory_layout.input_start && address < self.memory_layout.input_end
    }

    pub fn is_output(&self, address: u64) -> bool {
        address >= self.memory_layout.output_start && address < self.memory_layout.panic
    }

    pub fn is_panic(&self, address: u64) -> bool {
        address == self.memory_layout.panic
    }

    fn convert_read_address(&self, address: u64) -> usize {
        (address - self.memory_layout.input_start) as usize
    }

    fn convert_write_address(&self, address: u64) -> usize {
        (address - self.memory_layout.output_start) as usize
    }
}

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct MemoryLayout {
    pub ram_witness_offset: u64,
    pub max_input_size: u64,
    pub max_output_size: u64,
    pub input_start: u64,
    pub input_end: u64,
    pub output_start: u64,
    pub output_end: u64,
    pub panic: u64,
}

impl MemoryLayout {
    pub fn new(max_input_size: u64, max_output_size: u64) -> Self {
        Self {
            ram_witness_offset: ram_witness_offset(max_input_size, max_output_size),
            max_input_size,
            max_output_size,
            input_start: input_start(max_input_size, max_output_size),
            input_end: input_end(max_input_size, max_output_size),
            output_start: output_start(max_input_size, max_output_size),
            output_end: output_end(max_input_size, max_output_size),
            panic: panic_address(max_input_size, max_output_size),
        }
    }
}

pub fn ram_witness_offset(max_input: u64, max_output: u64) -> u64 {
    (REGISTER_COUNT + max_input + max_output + 1).next_power_of_two()
}

fn input_start(max_input: u64, max_output: u64) -> u64 {
    RAM_START_ADDRESS - ram_witness_offset(max_input, max_output) + REGISTER_COUNT
}

fn input_end(max_input: u64, max_output: u64) -> u64 {
    input_start(max_input, max_output) + max_input
}

fn output_start(max_input: u64, max_output: u64) -> u64 {
    input_end(max_input, max_output) + 1
}

fn output_end(max_input: u64, max_output: u64) -> u64 {
    output_start(max_input, max_output) + max_output
}

fn panic_address(max_input: u64, max_output: u64) -> u64 {
    output_end(max_input, max_output) + 1
}
