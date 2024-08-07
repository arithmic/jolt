use crate::{
    assert_static_aux_index, field::JoltField, impl_r1cs_input_lc_conversions, input_range,
    jolt::vm::rv32i_vm::C,
};

use super::{
    builder::{R1CSBuilder, R1CSConstraintBuilder},
    ops::{ConstraintInput, Variable, LC},
};

// TODO(#377): Dedupe OpFlags / CircuitFlags
// TODO(#378): Explicit unit test for comparing OpFlags and InstructionFlags
#[allow(non_camel_case_types)]
#[derive(
    strum_macros::EnumIter,
    strum_macros::EnumCount,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[repr(usize)]
pub enum JoltIn {
    PcIn,

    Bytecode_A, // Virtual address
    // Bytecode_V
    Bytecode_ELFAddress,
    Bytecode_Opcode,
    Bytecode_RS1,
    Bytecode_RS2,
    Bytecode_RD,
    Bytecode_Imm,

    RAM_A,
    // Ram_V
    RAM_Read_RS1,
    RAM_Read_RS2,
    RAM_Read_RD, // TODO(sragss): Appears to be unused?
    RAM_Read_Byte0,
    RAM_Read_Byte1,
    RAM_Read_Byte2,
    RAM_Read_Byte3,
    RAM_Write_RD,
    RAM_Write_Byte0,
    RAM_Write_Byte1,
    RAM_Write_Byte2,
    RAM_Write_Byte3,

    ChunksX_0,
    ChunksX_1,
    ChunksX_2,
    ChunksX_3,

    ChunksY_0,
    ChunksY_1,
    ChunksY_2,
    ChunksY_3,

    ChunksQ_0,
    ChunksQ_1,
    ChunksQ_2,
    ChunksQ_3,

    LookupOutput,

    // Should match rv_trace.to_circuit_flags()
    OpFlags_IsRs1Rs2,
    OpFlags_IsImm,
    OpFlags_IsLbu,
    OpFlags_IsLhu,
    OpFlags_IsLw,
    OpFlags_IsLb,
    OpFlags_IsLh,
    OpFlags_IsSb,
    OpFlags_IsSh,
    OpFlags_IsSw,
    OpFlags_IsJmp,
    OpFlags_IsBranch,
    OpFlags_LookupOutToRd,
    OpFlags_SignImm,
    OpFlags_IsConcat,
    OpFlags_IsVirtualSequence,
    OpFlags_IsVirtual,

    // Instruction Flags
    // Should match JoltInstructionSet
    IF_Add,
    IF_Sub,
    IF_And,
    IF_Or,
    IF_Xor,
    IF_Lb,
    IF_Lh,
    IF_Sb,
    IF_Sh,
    IF_Sw,
    IF_Beq,
    IF_Bge,
    IF_Bgeu,
    IF_Bne,
    IF_Slt,
    IF_Sltu,
    IF_Sll,
    IF_Sra,
    IF_Srl,
    IF_Movsign,
    IF_Mul,
    IF_MulU,
    IF_MulHu,

    // Remainder
    REM_LSB,
    REM_MSB,
}
impl_r1cs_input_lc_conversions!(JoltIn);
impl ConstraintInput for JoltIn {}

pub const PC_START_ADDRESS: i64 = 0x80000000;
const PC_NOOP_SHIFT: i64 = 4;
const LOG_M: usize = 16;
const OPERAND_SIZE: usize = LOG_M / 2;
//Changed PC_BRANCH_AUX_INDEX for new constraints
pub const PC_BRANCH_AUX_INDEX: usize = 44;

pub struct JoltConstraints {
    memory_start: u64,
}

impl JoltConstraints {
    pub fn new(memory_start: u64) -> Self {
        Self { memory_start }
    }
}

impl<F: JoltField> R1CSConstraintBuilder<F> for JoltConstraints {
    type Inputs = JoltIn;
    fn build_constraints(&self, cs: &mut R1CSBuilder<F, Self::Inputs>) {
        let flags = input_range!(JoltIn::OpFlags_IsRs1Rs2, JoltIn::IF_MulHu);
        for flag in flags {
            cs.constrain_binary(flag);
        }

        cs.constrain_eq(JoltIn::PcIn, JoltIn::Bytecode_A);

        cs.constrain_pack_be(flags.to_vec(), JoltIn::Bytecode_Opcode, 1);

        let real_pc = 4i64 * JoltIn::PcIn + (PC_START_ADDRESS - PC_NOOP_SHIFT);
        let x = cs.allocate_if_else(JoltIn::OpFlags_IsRs1Rs2, real_pc, JoltIn::RAM_Read_RS1);
        let y = cs.allocate_if_else(
            JoltIn::OpFlags_IsImm,
            JoltIn::Bytecode_Imm,
            JoltIn::RAM_Read_RS2,
        );

        // Converts from unsigned to twos-complement representation
        let signed_output = JoltIn::Bytecode_Imm - (0xffffffffi64 + 1i64);
        let imm_signed =
            cs.allocate_if_else(JoltIn::OpFlags_SignImm, signed_output, JoltIn::Bytecode_Imm);

        let packed_query: LC<JoltIn> = cs
            .allocate_pack_be(
                input_range!(JoltIn::ChunksQ_0, JoltIn::ChunksQ_3).to_vec(),
                LOG_M,
            )
            .into();

        cs.constrain_eq_conditional(JoltIn::IF_Add, packed_query.clone(), x + y);
        // Converts from unsigned to twos-complement representation
        cs.constrain_eq_conditional(
            JoltIn::IF_Sub,
            packed_query.clone(),
            x - y + (0xffffffffi64 + 1),
        );

        let rem_lsb: LC<JoltIn> = JoltIn::REM_LSB.into();
        let rem_msb: LC<JoltIn> = JoltIn::REM_MSB.into();
        let one_minus_rem_lsb = -rem_lsb.clone() + 1;
        let one_minus_rem_msb = -rem_msb.clone() + 1;
        //rem = rem_lsb + 2 * rem_msb
        let rem = JoltIn::REM_LSB + (JoltIn::REM_MSB * 2);

        //(1-rem_lsb) * (1-rem_msb)
        let product1 = cs.allocate_prod(one_minus_rem_lsb.clone(), one_minus_rem_msb.clone());
        //(rem_lsb) * (1-rem_msb)
        let product2 = cs.allocate_prod(rem_lsb.clone(), one_minus_rem_msb.clone());
        //(1-rem_lsb) * (rem_msb)
        let product3 = cs.allocate_prod(one_minus_rem_lsb.clone(), rem_msb.clone());
        //rem_lsb * rem_msb
        let product4 = cs.allocate_prod(rem_lsb.clone(), rem_msb.clone());

        cs.constrain_binary(rem_lsb.clone());
        cs.constrain_binary(rem_msb.clone());

        // (LH_flag + LHU_flag + SH_flag)
        let lh_lhu_sh_sum = JoltIn::OpFlags_IsLh + JoltIn::OpFlags_IsLhu + JoltIn::OpFlags_IsSh;
        // (LW_flag + SW_flag)
        let lw_sw_sum = JoltIn::OpFlags_IsLw + JoltIn::OpFlags_IsSw;
        // (LH_flag + LHU_flag + SH_flag) [remainder*(remainder -2)] + (LW_flag + SW_flag)*remainder
        let term1 = cs.allocate_prod(rem_lsb, lh_lhu_sh_sum);
        let term2 = cs.allocate_prod(rem.clone(), lw_sw_sum);
        cs.constrain_eq_zero(term1 + term2);

        // CONSTRAINT - actual_address is computed correctly using rs1_val, and imm_extension
        let flag_0_or_1_condition = JoltIn::OpFlags_IsLb
            + JoltIn::OpFlags_IsLbu
            + JoltIn::OpFlags_IsLh
            + JoltIn::OpFlags_IsLhu
            + JoltIn::OpFlags_IsLw
            + JoltIn::OpFlags_IsSb
            + JoltIn::OpFlags_IsSh
            + JoltIn::OpFlags_IsSw;

        let memory_start: i64 = self.memory_start.try_into().unwrap();
        let term: LC<JoltIn> = (Variable::Constant * memory_start).into();
        let r1 = term + rem.clone();
        let four_times: LC<JoltIn> = (JoltIn::RAM_A * 4).into();
        let actual_address = r1 + four_times;

        let imm_signed: LC<JoltIn> = imm_signed.into();
        let ram_read_rs1: LC<JoltIn> = JoltIn::RAM_Read_RS1.into();
        // let sum = ram_read_rs1 + imm_signed.clone();
        cs.constrain_eq_conditional(
            flag_0_or_1_condition,
            ram_read_rs1 + imm_signed.clone(),
            actual_address,
        );

        // LOAD CONSTRAINT a
        // For the load instructions, we have that the four bytes read at
        // index load_store_address of memory is the same as written
        let all_load_flags = JoltIn::OpFlags_IsLb
            + JoltIn::OpFlags_IsLbu
            + JoltIn::OpFlags_IsLh
            + JoltIn::OpFlags_IsLhu
            + JoltIn::OpFlags_IsLw;

        cs.constrain_eq_conditional(
            all_load_flags.clone(),
            JoltIn::RAM_Read_Byte0,
            JoltIn::RAM_Write_Byte0,
        );
        cs.constrain_eq_conditional(
            all_load_flags.clone(),
            JoltIn::RAM_Read_Byte1,
            JoltIn::RAM_Write_Byte1,
        );
        cs.constrain_eq_conditional(
            all_load_flags.clone(),
            JoltIn::RAM_Read_Byte2,
            JoltIn::RAM_Write_Byte2,
        );
        cs.constrain_eq_conditional(
            all_load_flags,
            JoltIn::RAM_Read_Byte3,
            JoltIn::RAM_Write_Byte3,
        );

        // LOAD CONSTRAINT b-1
        // (JoltIn::OpFlags_IsLb) [ (memory_read[0] - packed_query) *
        //                  (remainder - 1) * (remainder - 2) * (remainder - 3) +
        //                  (memory_read[1] - packed_query) * remainder * (remainder - 2) * (remainder - 3) +
        //                  (memory_read[2] - packed_query) * remainder * (remainder - 1) * (remainder - 3) +
        //                  (memory_read[3] - packed_query) * remainder * (remainder - 1) * (remainder - 2)
        //                  ] = 0
        let read0_minus_packed_query =
            cs.allocate_prod(JoltIn::RAM_Read_Byte0 - packed_query.clone(), product1);
        let read1_minus_packed_query =
            cs.allocate_prod(JoltIn::RAM_Read_Byte1 - packed_query.clone(), product2);
        let read2_minus_packed_query =
            cs.allocate_prod(JoltIn::RAM_Read_Byte2 - packed_query.clone(), product3);
        let read3_minus_packed_query =
            cs.allocate_prod(JoltIn::RAM_Read_Byte3 - packed_query.clone(), product4);

        let term0 = read0_minus_packed_query
            + read1_minus_packed_query
            + read2_minus_packed_query
            + read3_minus_packed_query;

        cs.constrain_eq_conditional(JoltIn::OpFlags_IsLb, term0, 0);

        // LOAD CONSTRAINT b-2
        // (LH_flag) [ (memory_read[0] + 2^{8}memory_read[1] - packed_query) * (remainder - 2)  +
        //                  (memory_read[2] + 2^{8}*memory_read[3] - packed_query) * remainder
        //                ] = 0
        let read01_memory = JoltIn::RAM_Read_Byte0 + JoltIn::RAM_Read_Byte1 * (1 << 8);
        let read23_memory = JoltIn::RAM_Read_Byte2 + JoltIn::RAM_Read_Byte3 * (1 << 8);

        let read01_minus_packed_query = cs.allocate_prod(
            read01_memory.clone() - packed_query.clone(),
            one_minus_rem_msb.clone(),
        );
        let read23_minus_packed_query = cs.allocate_prod(
            read23_memory.clone() - packed_query.clone(),
            rem_msb.clone(),
        );
        let term1 = read01_minus_packed_query + read23_minus_packed_query;
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsLh, term1, 0);

        // LOAD CONSTRAINT b-3
        // (LW_flag) [ memory_read[0] + 2^{8}memory_read[1] + 2^{16}memory_read[2] +
        //                  2^{24}memory_read[3]  - combined_z_chunks) ] = 0

        let read_memory = (JoltIn::RAM_Read_Byte0 + JoltIn::RAM_Read_Byte1 * (1 << 8))
            + (JoltIn::RAM_Read_Byte2 * (1 << 16) + JoltIn::RAM_Read_Byte3 * (1 << 24));

        cs.constrain_eq_conditional(
            JoltIn::OpFlags_IsLw,
            read_memory.clone() - packed_query.clone(),
            0,
        );

        //STORE CONSTRAINT a2
        // (LBU_flag)[ remainder123 * (memory_read[0] - JoltIn::ChunksQ_3) + remainder023 * (memory_read[1] - JoltIn::ChunksQ_3)
        //          + remainder013 * (memory_read[2] - JoltIn::ChunksQ_3) + remainder012 * (memory_read[3] - JoltIn::ChunksQ_3)
        //           ] = 0
        let read_equal_lookup_index0 =
            cs.allocate_prod(JoltIn::RAM_Read_Byte0 - JoltIn::ChunksQ_3, product1);

        let read_equal_lookup_index1 =
            cs.allocate_prod(JoltIn::RAM_Read_Byte1 - JoltIn::ChunksQ_3, product2);

        let read_equal_lookup_index2 =
            cs.allocate_prod(JoltIn::RAM_Read_Byte2 - JoltIn::ChunksQ_3, product3);

        let read_equal_lookup_index3 =
            cs.allocate_prod(JoltIn::RAM_Read_Byte3 - JoltIn::ChunksQ_3, product4);
        let term = read_equal_lookup_index0
            + read_equal_lookup_index1
            + read_equal_lookup_index2
            + read_equal_lookup_index3;

        cs.constrain_eq_conditional(JoltIn::OpFlags_IsLbu, term, 0);

        //LOAD CONSTRAINT d1

        // (LHU_flag)[ (remainder-2) * (memory_read[0] + memory_read[1] * 2^{8} - JoltIn::ChunksQ_3) +
        //    remainder * (memory_read[2] + memory_read[3] * 2^{8} - JoltIn::ChunksQ_3)
        //           ] = 0

        let read_equal_lookup_index01 = cs.allocate_prod(
            read01_memory.clone() - JoltIn::ChunksQ_3.into(),
            one_minus_rem_msb.clone(),
        );
        let read_equal_lookup_index23 = cs.allocate_prod(
            read23_memory.clone() - JoltIn::ChunksQ_3.into(),
            rem_msb.clone(),
        );
        cs.constrain_eq_conditional(
            JoltIn::OpFlags_IsLhu,
            read_equal_lookup_index01 + read_equal_lookup_index23,
            0,
        );

        // LOAD CONSTRAINT d2
        // Constraint to check rd is updated with lookup output
        // check this constraint later
        let rd_nonzero_and_lookup_to_rd =
            cs.allocate_prod(JoltIn::Bytecode_RD, JoltIn::OpFlags_LookupOutToRd);
        cs.constrain_eq_conditional(
            rd_nonzero_and_lookup_to_rd,
            JoltIn::RAM_Write_RD,
            JoltIn::LookupOutput,
        );

        // STORE CONSTRAINT a1
        // (SB_flag + SH_flag + SW_flag) [ rs2_val - packed_query]
        let all_store_flags = JoltIn::OpFlags_IsSb + JoltIn::OpFlags_IsSh + JoltIn::OpFlags_IsSw;

        cs.constrain_eq_conditional(
            all_store_flags,
            JoltIn::RAM_Read_RS2 - packed_query.clone(),
            0,
        );

        // STORE CONSTRAINT b-1
        // (SB_flag) [
        //           (memory_write[0]  - lookup_output) *  (remainder - 1) (remainder - 2) * (remainder - 3) +
        //           (memory_write[1] - lookup_output) * remainder * (remainder - 2) * (remainder - 3) +
        //           (memory_write[2] - lookup_output) * remainder * (remainder - 1) * (remainder - 3) +
        //           (memory_write[3] - lookup_output) * remainder * (remainder - 1) * (remainder - 2)
        //       ] = 0

        let write0_minus_lookupoutput =
            cs.allocate_prod(JoltIn::RAM_Write_Byte0 - JoltIn::LookupOutput, product1);
        let write1_minus_lookupoutput =
            cs.allocate_prod(JoltIn::RAM_Write_Byte1 - JoltIn::LookupOutput, product2);
        let write2_minus_lookupoutput =
            cs.allocate_prod(JoltIn::RAM_Write_Byte2 - JoltIn::LookupOutput, product3);
        let write3_minus_lookupoutput =
            cs.allocate_prod(JoltIn::RAM_Write_Byte3 - JoltIn::LookupOutput, product4);
        let term0 = write0_minus_lookupoutput
            + write1_minus_lookupoutput
            + write2_minus_lookupoutput
            + write3_minus_lookupoutput;

        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSb, term0, 0);

        // STORE CONSTRAINT b-2
        // (SH_flag) [
        //           (memory_write[0] + 2^{8}memory_write[1] - lookup_output) * (remainder - 2)  +
        //           (memory_write[2] +  2^{8}*memory_write[3] - lookup_output) * remainder
        //     ] = 0
        let write01_memory = JoltIn::RAM_Write_Byte0 + JoltIn::RAM_Write_Byte1 * (1 << 8);
        let write23_memory = JoltIn::RAM_Write_Byte2 + JoltIn::RAM_Write_Byte3 + (1 << 8);

        let write01_minus_lookupoutput = cs.allocate_prod(
            write01_memory.clone() - JoltIn::LookupOutput.into(),
            one_minus_rem_msb.clone(),
        );
        let write23_minus_lookupoutput = cs.allocate_prod(
            write23_memory.clone() - JoltIn::LookupOutput.into(),
            rem_msb.clone(),
        );
        let term1 = write01_minus_lookupoutput + write23_minus_lookupoutput;
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSh, term1, 0);

        // STORE CONSTRAINT b-3
        // (SW_flag) [
        //           memory_write[0] + 2^{8}memory_write[1] +
        //           2^{16}memory_write[2] + 2^{24}memory_write[3]  -
        //           packed_query)
        //           ] = 0

        let write_memory = (JoltIn::RAM_Write_Byte0 + JoltIn::RAM_Write_Byte1 * (1 << 8))
            + (JoltIn::RAM_Write_Byte2 * (1 << 16) + JoltIn::RAM_Write_Byte3 * (1 << 24));
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSw, write_memory - packed_query, 0);

        // STORE CONSTRAINT c-1
        // (JoltIn::OpFlags_IsSh) [remainder  (memory_read[0] + memory[1] * 2^{8} - memory_write[0] - memory_write[1]* 2^{8})] +
        //   (remainder -2)(memory_read[2] + memory[3] * 2^{8} - memory_write[2] - memory_write[3]* 2^{8})]

        let term0 = cs.allocate_prod(read01_memory - write01_memory, rem_msb);
        let term1 = cs.allocate_prod(read23_memory - write23_memory, one_minus_rem_msb);
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSh, term0 + term1, 0);

        // STORE CONSTRAINT c-2
        // (JoltIn::OpFlags_IsSb) * remainder (memory_read[0] - memory_write[0])
        //  (JoltIn::OpFlags_IsSb) * (remainder -1) (memory_read[1] - memory_write[1]) ]
        //  (JoltIn::OpFlags_IsSb) * (remainder -2) (memory_read[2] - memory_write[2]) ]
        //  (JoltIn::OpFlags_IsSb) * (remainder -3) (memory_read[3] - memory_write[3]) ]

        let read_equal_write0 = cs.allocate_prod(
            JoltIn::RAM_Read_Byte0 - JoltIn::RAM_Write_Byte0,
            rem.clone(),
        );

        let read_equal_write1 = cs.allocate_prod(
            JoltIn::RAM_Read_Byte1 - JoltIn::RAM_Write_Byte1,
            -rem.clone() + 1,
        );

        let read_equal_write2 = cs.allocate_prod(
            JoltIn::RAM_Read_Byte2 - JoltIn::RAM_Write_Byte2,
            -rem.clone() + 2,
        );

        let read_equal_write3 = cs.allocate_prod(
            JoltIn::RAM_Read_Byte3 - JoltIn::RAM_Write_Byte3,
            -rem.clone() + 3,
        );

        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSb, read_equal_write0, 0);
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSb, read_equal_write1, 0);
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSb, read_equal_write2, 0);
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsSb, read_equal_write3, 0);

        // TODO(sragss): Uses 2 excess constraints for condition gating. Could make constrain_pack_be_conditional... Or make everything conditional...
        let chunked_x = cs.allocate_pack_be(
            input_range!(JoltIn::ChunksX_0, JoltIn::ChunksX_3).to_vec(),
            OPERAND_SIZE,
        );
        let chunked_y = cs.allocate_pack_be(
            input_range!(JoltIn::ChunksY_0, JoltIn::ChunksY_3).to_vec(),
            OPERAND_SIZE,
        );
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsConcat, chunked_x, x);
        cs.constrain_eq_conditional(JoltIn::OpFlags_IsConcat, chunked_y, y);

        // if is_shift ? chunks_query[i] == zip(chunks_x[i], chunks_y[C-1]) : chunks_query[i] == zip(chunks_x[i], chunks_y[i])
        let is_shift = JoltIn::IF_Sll + JoltIn::IF_Srl + JoltIn::IF_Sra;
        let chunks_x = input_range!(JoltIn::ChunksX_0, JoltIn::ChunksX_3);
        let chunks_y = input_range!(JoltIn::ChunksY_0, JoltIn::ChunksY_3);
        let chunks_query = input_range!(JoltIn::ChunksQ_0, JoltIn::ChunksQ_3);
        for i in 0..C {
            let relevant_chunk_y =
                cs.allocate_if_else(is_shift.clone(), chunks_y[C - 1], chunks_y[i]);
            cs.constrain_eq_conditional(
                JoltIn::OpFlags_IsConcat,
                chunks_query[i],
                (1i64 << 8) * chunks_x[i] + relevant_chunk_y,
            );
        }

        // if (rd != 0 && update_rd_with_lookup_output == 1) constrain(rd_val == LookupOutput)
        // if (rd != 0 && is_jump_instr == 1) constrain(rd_val == 4 * PC)

        let rd_nonzero_and_jmp = cs.allocate_prod(JoltIn::Bytecode_RD, JoltIn::OpFlags_IsJmp);
        let lhs = JoltIn::PcIn + (PC_START_ADDRESS - PC_NOOP_SHIFT);
        let rhs = JoltIn::RAM_Write_RD;
        cs.constrain_eq_conditional(rd_nonzero_and_jmp, lhs, rhs);

        let branch_and_lookup_output =
            cs.allocate_prod(JoltIn::OpFlags_IsBranch, JoltIn::LookupOutput);
        let next_pc_jump = cs.allocate_if_else(
            JoltIn::OpFlags_IsJmp,
            JoltIn::LookupOutput + 4,
            4 * JoltIn::PcIn + PC_START_ADDRESS + 4,
        );

        let next_pc_jump_branch = cs.allocate_if_else(
            branch_and_lookup_output,
            4 * JoltIn::PcIn + PC_START_ADDRESS + imm_signed,
            next_pc_jump,
        );

        assert_static_aux_index!(next_pc_jump_branch, PC_BRANCH_AUX_INDEX);
    }
}
