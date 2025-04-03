#![allow(
    clippy::len_without_is_empty,
    clippy::type_complexity,
    clippy::too_many_arguments
)]

use crate::impl_r1cs_input_lc_conversions;
use crate::jolt::instruction::JoltInstructionSet;
use crate::jolt::vm::bytecode::{BytecodeStuff, StreamingBytecodeStuff};
use crate::jolt::vm::instruction_lookups::{
    InstructionLookupStuff, StreamingInstructionLookupStuff,
};
use crate::jolt::vm::read_write_memory::{
    return_v_init, ReadWriteMemoryStuff, StreamingReadWriteMemoryStuff,
};
use crate::jolt::vm::rv32i_vm::RV32I;
use crate::jolt::vm::timestamp_range_check::TimestampRangeCheckStuff;
use crate::jolt::vm::{JoltCommitments, JoltPreprocessing, JoltStuff, JoltTraceStep};
use crate::lasso::memory_checking::{Initializable, StructuredPolynomialData};
use crate::poly::commitment::commitment_scheme::CommitmentScheme;
use crate::poly::multilinear_polynomial::MultilinearPolynomial;
use crate::poly::opening_proof::VerifierOpeningAccumulator;
use crate::poly::streaming_poly::StreamingOracle;
use crate::utils::transcript::Transcript;

use super::builder::CombinedUniformBuilder;
use super::key::UniformSpartanKey;
use super::spartan::{SpartanError, UniformSpartanProof};

use crate::field::JoltField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use common::rv_trace::{CircuitFlags, NUM_CIRCUIT_FLAGS};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::fmt::Debug;
use std::marker::PhantomData;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tracer::JoltDevice;

/// Auxiliary variables defined in Jolt's R1CS constraints.
#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuxVariableStuff<T: CanonicalSerialize + CanonicalDeserialize> {
    pub left_lookup_operand: T,
    pub right_lookup_operand: T,
    pub product: T,
    pub relevant_y_chunks: Vec<T>,
    pub write_lookup_output_to_rd: T,
    pub write_pc_to_rd: T,
    pub next_pc_jump: T,
    pub should_branch: T,
    pub next_pc: T,
}

impl<T: CanonicalSerialize + CanonicalDeserialize + Default> Initializable<T, usize>
    for AuxVariableStuff<T>
{
    #[allow(clippy::field_reassign_with_default)]
    fn initialize(C: &usize) -> Self {
        let mut result = Self::default();
        result.relevant_y_chunks = std::iter::repeat_with(|| T::default()).take(*C).collect();
        result
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> StructuredPolynomialData<T>
    for AuxVariableStuff<T>
{
    fn read_write_values(&self) -> Vec<&T> {
        let mut values = vec![
            &self.left_lookup_operand,
            &self.right_lookup_operand,
            &self.product,
        ];
        values.extend(self.relevant_y_chunks.iter());
        values.extend([
            &self.write_lookup_output_to_rd,
            &self.write_pc_to_rd,
            &self.next_pc_jump,
            &self.should_branch,
            &self.next_pc,
        ]);
        values
    }

    fn read_write_values_mut(&mut self) -> Vec<&mut T> {
        let mut values = vec![
            &mut self.left_lookup_operand,
            &mut self.right_lookup_operand,
            &mut self.product,
        ];
        values.extend(self.relevant_y_chunks.iter_mut());
        values.extend([
            &mut self.write_lookup_output_to_rd,
            &mut self.write_pc_to_rd,
            &mut self.next_pc_jump,
            &mut self.should_branch,
            &mut self.next_pc,
        ]);
        values
    }
}

#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSStuff<T: CanonicalSerialize + CanonicalDeserialize> {
    pub chunks_x: Vec<T>,
    pub chunks_y: Vec<T>,
    pub circuit_flags: [T; NUM_CIRCUIT_FLAGS],
    pub aux: AuxVariableStuff<T>,
}

impl<T: CanonicalSerialize + CanonicalDeserialize + Default> Initializable<T, usize>
    for R1CSStuff<T>
{
    fn initialize(C: &usize) -> Self {
        Self {
            chunks_x: std::iter::repeat_with(|| T::default()).take(*C).collect(),
            chunks_y: std::iter::repeat_with(|| T::default()).take(*C).collect(),
            circuit_flags: std::array::from_fn(|_| T::default()),
            aux: AuxVariableStuff::initialize(C),
        }
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> StructuredPolynomialData<T> for R1CSStuff<T> {
    fn read_write_values(&self) -> Vec<&T> {
        self.chunks_x
            .iter()
            .chain(self.chunks_y.iter())
            .chain(self.circuit_flags.iter())
            .chain(self.aux.read_write_values())
            .collect()
    }

    fn read_write_values_mut(&mut self) -> Vec<&mut T> {
        self.chunks_x
            .iter_mut()
            .chain(self.chunks_y.iter_mut())
            .chain(self.circuit_flags.iter_mut())
            .chain(self.aux.read_write_values_mut())
            .collect()
    }
}

pub struct StreamingR1CSStuff<
    'a,
    const C: usize,
    const M: usize,
    I: Iterator,
    F: JoltField,
    PCS: CommitmentScheme<ProofTranscript, Field = F>,
    ProofTranscript: Transcript,
    CI: ConstraintInput,
> {
    pub(crate) trace_iter: I,
    pub(crate) init_iter: I,
    pub(crate) r1cs_builder: &'a CombinedUniformBuilder<C, F, CI>,
    pub(crate) jolt_preprocessing: &'a JoltPreprocessing<C, F, PCS, ProofTranscript>,
    pub(crate) program_io: &'a JoltDevice,
    pub(crate) shard: R1CSStuff<MultilinearPolynomial<F>>,
    pub(crate) v_init: Vec<u32>,
    pub(crate) v_final: Vec<u32>,
}

impl<
        'a,
        const C: usize,
        const M: usize,
        IS: JoltInstructionSet,
        I: Iterator<Item = JoltTraceStep<IS>> + Clone,
        F: JoltField,
        PCS: CommitmentScheme<ProofTranscript, Field = F>,
        ProofTranscript: Transcript,
        CI: ConstraintInput,
    > StreamingR1CSStuff<'a, C, M, I, F, PCS, ProofTranscript, CI>
{
    pub fn new(
        trace_iter: I,
        shard_len: usize,
        r1cs_builder: &'a CombinedUniformBuilder<C, F, CI>,
        jolt_preprocessing: &'a JoltPreprocessing<C, F, PCS, ProofTranscript>,
        program_io: &'a JoltDevice,
    ) -> Self {
        let v_init = return_v_init(
            trace_iter.clone(),
            &jolt_preprocessing.read_write_memory,
            program_io,
        );
        let v_final = v_init.clone();

        (return StreamingR1CSStuff {
            trace_iter: trace_iter.clone(),
            init_iter: trace_iter.clone(),
            shard: R1CSStuff {
                chunks_x: vec![MultilinearPolynomial::from(vec![0u8; shard_len]); C],
                chunks_y: vec![MultilinearPolynomial::from(vec![0u8; shard_len]); C],
                circuit_flags: [
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                    MultilinearPolynomial::from(vec![0u8; shard_len]),
                ],
                aux: AuxVariableStuff::default(),
            },
            r1cs_builder: &r1cs_builder,
            jolt_preprocessing: &jolt_preprocessing,
            program_io: &program_io,
            v_init,
            v_final,
        });
    }
}

impl<
        const C: usize,
        const M: usize,
        IS: JoltInstructionSet,
        I: Iterator<Item = JoltTraceStep<IS>> + Clone,
        F: JoltField,
        PCS: CommitmentScheme<ProofTranscript, Field = F>,
        ProofTranscript: Transcript,
        CI: ConstraintInput,
    > StreamingOracle<I> for StreamingR1CSStuff<'_, C, M, I, F, PCS, ProofTranscript, CI>
{
    fn stream_next_shard(&mut self, shard_len: usize) {
        let mut global_instruction_stuff: InstructionLookupStuff<MultilinearPolynomial<F>> =
            InstructionLookupStuff::initialize(&self.jolt_preprocessing.instruction_lookups);
        let mut global_bytecode_stuff: BytecodeStuff<MultilinearPolynomial<F>> =
            BytecodeStuff::default();
        let mut global_rw_mem_stuff: ReadWriteMemoryStuff<MultilinearPolynomial<F>> =
            ReadWriteMemoryStuff::default();
        global_bytecode_stuff.v_read_write = [
            MultilinearPolynomial::from(vec![0u64; shard_len]),
            MultilinearPolynomial::from(vec![0u64; shard_len]),
            MultilinearPolynomial::from(vec![0u8; shard_len]),
            MultilinearPolynomial::from(vec![0u8; shard_len]),
            MultilinearPolynomial::from(vec![0u8; shard_len]),
            MultilinearPolynomial::from(vec![0i64; shard_len]),
        ];

        let mut dim = vec![vec![0u16; shard_len]; C];
        let mut E_polys = vec![vec![0u32; shard_len]; global_instruction_stuff.E_polys.len()];
        let mut instruction_flags =
            vec![vec![0u8; shard_len]; global_instruction_stuff.instruction_flags.len()];

        let mut lookup_outputs = vec![0u32; shard_len];

        let mut a_read_write = vec![0u32; shard_len];
        let mut v_read_write_0_1_vec = vec![vec![0u64; shard_len]; 2];
        let mut v_read_write_2_4_vec = vec![vec![0u8; shard_len]; 3];
        let mut v_read_write_5_vec = vec![0i64; shard_len];

        let mut a_ram = vec![0u32; shard_len];
        let mut v_read_rd = vec![0u32; shard_len];
        let mut v_read_rs1 = vec![0u32; shard_len];
        let mut v_read_rs2 = vec![0u32; shard_len];
        let mut v_read_ram = vec![0u32; shard_len];
        let mut v_write_rd = vec![0u32; shard_len];
        let mut v_write_ram = vec![0u32; shard_len];

        let mut chunks_x = vec![vec![0u8; shard_len]; C];
        let mut chunks_y = vec![vec![0u8; shard_len]; C];
        let mut circuit_flags = vec![vec![0u8; shard_len]; NUM_CIRCUIT_FLAGS];

        for shard in 0..shard_len {
            if let Some(mut step) = self.trace_iter.next() {
                let (dim_temp, E_polys_temp, instruction_flags_temp, lookup_outputs_temp) = StreamingInstructionLookupStuff::<I, F, C, M>::generate_witness_instructionlookups_streaming(
                    &step,
                    &self.jolt_preprocessing.instruction_lookups,
                );

                let rw_mem_stuff =
                    StreamingReadWriteMemoryStuff::<I, F>::generate_witness_rw_memory_streaming(
                        &step,
                        self.program_io,
                        &mut self.v_final,
                    );

                let (
                    a_read_write_temp,
                    v_read_write_0_1_temp,
                    v_read_write_2_4_temp,
                    v_read_write_5_temp,
                ) = StreamingBytecodeStuff::<I, F>::generate_witness_bytecode_streaming(
                    &mut step,
                    &self.jolt_preprocessing.bytecode,
                );

                // collecting in global stuffs
                // 1 ------------ // instruction_stuff
                for idx in 0..dim_temp.len() {
                    dim[idx][shard] = dim_temp[idx];
                }

                for idx in 0..E_polys_temp.len() {
                    E_polys[idx][shard] = E_polys_temp[idx];
                }

                for idx in 0..instruction_flags_temp.len() {
                    instruction_flags[idx][shard] = instruction_flags_temp[idx];
                }

                lookup_outputs[shard] = lookup_outputs_temp;
                // ------------ //

                // 2 ------------ // bytecode_stuff
                // global_bytecode_stuff.a_read_write.push(bytecode_stuff.a_read_write);
                a_read_write[shard] = a_read_write_temp;

                v_read_write_0_1_vec[0][shard] = v_read_write_0_1_temp[0];
                v_read_write_0_1_vec[1][shard] = v_read_write_0_1_temp[1];
                v_read_write_2_4_vec[0][shard] = v_read_write_2_4_temp[0];
                v_read_write_2_4_vec[1][shard] = v_read_write_2_4_temp[1];
                v_read_write_2_4_vec[2][shard] = v_read_write_2_4_temp[2];
                v_read_write_5_vec[shard] = v_read_write_5_temp;

                // ------------ //
                // 3 ------------ // read_write_memory_stuff
                a_ram[shard] = rw_mem_stuff.a_ram;
                v_read_rs1[shard] = rw_mem_stuff.v_read_rs1;
                v_read_rs2[shard] = rw_mem_stuff.v_read_rs2;
                v_read_rd[shard] = rw_mem_stuff.v_read_rd;
                v_read_ram[shard] = rw_mem_stuff.v_read_ram;
                v_write_rd[shard] = rw_mem_stuff.v_write_rd;
                v_write_ram[shard] = rw_mem_stuff.v_write_ram;
                // ------------ //

                let mut chunks_x_temp = vec![0u8; C];
                let mut chunks_y_temp = vec![0u8; C];

                if let Some(instr) = &step.instruction_lookup {
                    let (x, y) = instr.operand_chunks(C, log2(M) as usize);
                    for j in 0..C {
                        chunks_x_temp[j] = x[j];
                        chunks_y_temp[j] = y[j];
                    }
                }

                for j in 0..C {
                    chunks_x[j][shard] = chunks_x_temp.clone()[j];
                    chunks_y[j][shard] = chunks_y_temp.clone()[j];
                }

                let mut circuit_flags_temp = [0u8; NUM_CIRCUIT_FLAGS];
                for j in 0..NUM_CIRCUIT_FLAGS {
                    circuit_flags_temp[j] = step.circuit_flags[j] as u8;
                }
                for j in 0..NUM_CIRCUIT_FLAGS {
                    circuit_flags[j][shard] = circuit_flags_temp[j];
                }
            }
        }

        // ----- instruction stuff -------
        global_instruction_stuff.dim = dim
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
        global_instruction_stuff.E_polys = E_polys
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
        global_instruction_stuff.instruction_flags = instruction_flags
            .clone()
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
        global_instruction_stuff.lookup_outputs = MultilinearPolynomial::from(lookup_outputs);

        // ----- bytecode stuff -------
        global_bytecode_stuff.a_read_write = MultilinearPolynomial::from(a_read_write);
        (0..2).for_each(|idx| {
            global_bytecode_stuff.v_read_write[idx] =
                MultilinearPolynomial::from(v_read_write_0_1_vec[idx].clone());
        });

        (0..3).for_each(|idx| {
            global_bytecode_stuff.v_read_write[2 + idx] =
                MultilinearPolynomial::from(v_read_write_2_4_vec[idx].clone());
        });
        global_bytecode_stuff.v_read_write[5] = MultilinearPolynomial::from(v_read_write_5_vec);

        // ---- read write memory stuff -----
        global_rw_mem_stuff.a_ram = MultilinearPolynomial::from(a_ram);
        global_rw_mem_stuff.v_read_rd = MultilinearPolynomial::from(v_read_rd);
        global_rw_mem_stuff.v_read_rs1 = MultilinearPolynomial::from(v_read_rs1);
        global_rw_mem_stuff.v_read_rs2 = MultilinearPolynomial::from(v_read_rs2);
        global_rw_mem_stuff.v_read_ram = MultilinearPolynomial::from(v_read_ram);
        global_rw_mem_stuff.v_write_rd = MultilinearPolynomial::from(v_write_rd);
        global_rw_mem_stuff.v_write_ram = MultilinearPolynomial::from(v_write_ram);

        // ----- r1cs stuff -----
        self.shard.chunks_x = chunks_x
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
        self.shard.chunks_y = chunks_y
            .into_par_iter()
            .map(MultilinearPolynomial::from)
            .collect();
        for i in 0..NUM_CIRCUIT_FLAGS {
            self.shard.circuit_flags[i] = MultilinearPolynomial::from(circuit_flags[i].clone())
        }

        let r1cs_stuff = R1CSStuff {
            chunks_x: self.shard.chunks_x.clone(),
            chunks_y: self.shard.chunks_y.clone(),
            circuit_flags: self.shard.circuit_flags.clone(),
            aux: AuxVariableStuff::initialize(&C),
        };

        let mut jolt_poly = JoltStuff {
            bytecode: global_bytecode_stuff,
            read_write_memory: global_rw_mem_stuff,
            instruction_lookups: global_instruction_stuff,
            r1cs: r1cs_stuff,
            timestamp_range_check: TimestampRangeCheckStuff::default(),
        };

        self.r1cs_builder.compute_aux_(&mut jolt_poly, shard_len);
        self.shard.aux = jolt_poly.r1cs.aux;
    }
}

/// Witness polynomials specific to Jolt's R1CS constraints (i.e. not used
/// for any offline memory-checking instances).
///
/// Note –– F: JoltField bound is not enforced.
/// See issue #112792 <https://github.com/rust-lang/rust/issues/112792>.
/// Adding #![feature(lazy_type_alias)] to the crate attributes seem to break
/// `alloy_sol_types`.
pub type R1CSPolynomials<F: JoltField> = R1CSStuff<MultilinearPolynomial<F>>;
/// Openings specific to Jolt's R1CS constraints (i.e. not used
/// for any offline memory-checking instances).
///
/// Note –– F: JoltField bound is not enforced.
/// See issue #112792 <https://github.com/rust-lang/rust/issues/112792>.
/// Adding #![feature(lazy_type_alias)] to the crate attributes seem to break
/// `alloy_sol_types`.
pub type R1CSOpenings<F: JoltField> = R1CSStuff<F>;
/// Commitments specific to Jolt's R1CS constraints (i.e. not used
/// for any offline memory-checking instances).
///
/// Note –– PCS: CommitmentScheme bound is not enforced.
/// See issue #112792 <https://github.com/rust-lang/rust/issues/112792>.
/// Adding #![feature(lazy_type_alias)] to the crate attributes seem to break
/// `alloy_sol_types`.
pub type R1CSCommitments<PCS: CommitmentScheme<ProofTranscript>, ProofTranscript: Transcript> =
    R1CSStuff<PCS::Commitment>;

impl<F: JoltField> R1CSPolynomials<F> {
    #[tracing::instrument(skip_all, name = "R1CSPolynomials::new")]
    pub fn new<
        const C: usize,
        const M: usize,
        InstructionSet: JoltInstructionSet,
        I: ConstraintInput,
    >(
        trace: &[JoltTraceStep<InstructionSet>],
    ) -> Self {
        let log_M = log2(M) as usize;

        let mut chunks_x = vec![vec![0u8; trace.len()]; C];
        let mut chunks_y = vec![vec![0u8; trace.len()]; C];
        let mut circuit_flags = vec![vec![0u8; trace.len()]; NUM_CIRCUIT_FLAGS];

        // TODO(moodlezoup): Can be parallelized
        for (step_index, step) in trace.iter().enumerate() {
            if let Some(instr) = &step.instruction_lookup {
                let (x, y) = instr.operand_chunks(C, log_M);
                for i in 0..C {
                    chunks_x[i][step_index] = x[i];
                    chunks_y[i][step_index] = y[i];
                }
            }

            for j in 0..NUM_CIRCUIT_FLAGS {
                if step.circuit_flags[j] {
                    circuit_flags[j][step_index] = 1;
                }
            }
        }

        Self {
            chunks_x: chunks_x
                .into_iter()
                .map(MultilinearPolynomial::from)
                .collect(),
            chunks_y: chunks_y
                .into_iter()
                .map(MultilinearPolynomial::from)
                .collect(),
            circuit_flags: circuit_flags
                .into_iter()
                .map(MultilinearPolynomial::from)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            // Actual aux variable polynomials will be computed afterwards
            aux: AuxVariableStuff::initialize(&C),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSProof<const C: usize, I: ConstraintInput, F: JoltField, ProofTranscript: Transcript>
{
    pub key: UniformSpartanKey<C, I, F>,
    pub proof: UniformSpartanProof<C, I, F, ProofTranscript>,
    pub _marker: PhantomData<ProofTranscript>,
}

impl<const C: usize, I: ConstraintInput, F: JoltField, ProofTranscript: Transcript>
    R1CSProof<C, I, F, ProofTranscript>
{
    #[tracing::instrument(skip_all, name = "R1CSProof::verify")]
    pub fn verify<PCS>(
        &self,
        commitments: &JoltCommitments<PCS, ProofTranscript>,
        opening_accumulator: &mut VerifierOpeningAccumulator<F, PCS, ProofTranscript>,
        transcript: &mut ProofTranscript,
    ) -> Result<(), SpartanError>
    where
        PCS: CommitmentScheme<ProofTranscript, Field = F>,
        ProofTranscript: Transcript,
    {
        self.proof
            .verify(&self.key, commitments, opening_accumulator, transcript)
    }
}

/// Jolt's R1CS constraint inputs are typically represented as an enum.
/// This trait serves two main purposes:
/// - Defines a canonical ordering over inputs (and thus indices for each input).
///   This is needed for sumcheck.
/// - Defines a mapping between inputs and Jolt's polynomial/commitment/opening types
///   (i.e. `JoltStuff<T>`).
pub trait ConstraintInput: Clone + Copy + Debug + PartialEq + Sync + Send + 'static {
    /// Returns a flat vector of all unique constraint inputs.
    /// This also serves as a canonical ordering over the inputs.
    fn flatten<const C: usize>() -> Vec<Self>;

    /// The total number of unique constraint inputs
    fn num_inputs<const C: usize>() -> usize {
        Self::flatten::<C>().len()
    }

    /// Converts an index to the corresponding constraint input.
    fn from_index<const C: usize>(index: usize) -> Self {
        Self::flatten::<C>()[index]
    }

    /// Converts a constraint input to its index in the canonical
    /// ordering over inputs given by `ConstraintInput::flatten`.
    fn to_index<const C: usize>(&self) -> usize {
        match Self::flatten::<C>().iter().position(|x| x == self) {
            Some(index) => index,
            None => panic!("Invalid variant {:?}", self),
        }
    }

    /// Gets an immutable reference to a Jolt polynomial/commitment/opening
    /// corresponding to the given constraint input.
    fn get_ref<'a, T: CanonicalSerialize + CanonicalDeserialize + Sync>(
        &self,
        jolt_stuff: &'a JoltStuff<T>,
    ) -> &'a T;

    /// Gets a mutable reference to a Jolt polynomial/commitment/opening
    /// corresponding to the given constraint input.
    fn get_ref_mut<'a, T: CanonicalSerialize + CanonicalDeserialize + Sync>(
        &self,
        jolt_stuff: &'a mut JoltStuff<T>,
    ) -> &'a mut T;
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, EnumIter)]
pub enum JoltR1CSInputs {
    Bytecode_A, // Virtual address
    // Bytecode_V
    Bytecode_ELFAddress,
    Bytecode_Bitflags,
    Bytecode_RS1,
    Bytecode_RS2,
    Bytecode_RD,
    Bytecode_Imm,

    RAM_Address,
    RS1_Read,
    RS2_Read,
    RD_Read,
    RAM_Read,
    RD_Write,
    RAM_Write,

    ChunksQuery(usize),
    LookupOutput,
    ChunksX(usize),
    ChunksY(usize),

    OpFlags(CircuitFlags),
    InstructionFlags(RV32I),
    Aux(AuxVariable),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, EnumIter)]
pub enum AuxVariable {
    #[default] // Need a default so that we can derive EnumIter on `JoltR1CSInputs`
    LeftLookupOperand,
    RightLookupOperand,
    Product,
    RelevantYChunk(usize),
    WriteLookupOutputToRD,
    WritePCtoRD,
    NextPCJump,
    ShouldBranch,
    NextPC,
}

impl_r1cs_input_lc_conversions!(JoltR1CSInputs, 4);
impl ConstraintInput for JoltR1CSInputs {
    fn flatten<const C: usize>() -> Vec<Self> {
        JoltR1CSInputs::iter()
            .flat_map(|variant| match variant {
                Self::ChunksQuery(_) => (0..C).map(Self::ChunksQuery).collect(),
                Self::ChunksX(_) => (0..C).map(Self::ChunksX).collect(),
                Self::ChunksY(_) => (0..C).map(Self::ChunksY).collect(),
                Self::OpFlags(_) => CircuitFlags::iter().map(Self::OpFlags).collect(),
                Self::InstructionFlags(_) => RV32I::iter().map(Self::InstructionFlags).collect(),
                Self::Aux(_) => AuxVariable::iter()
                    .flat_map(|aux| match aux {
                        AuxVariable::RelevantYChunk(_) => (0..C)
                            .map(|i| Self::Aux(AuxVariable::RelevantYChunk(i)))
                            .collect(),
                        _ => vec![Self::Aux(aux)],
                    })
                    .collect(),
                _ => vec![variant],
            })
            .collect()
    }

    fn get_ref<'a, T: CanonicalSerialize + CanonicalDeserialize + Sync>(
        &self,
        jolt: &'a JoltStuff<T>,
    ) -> &'a T {
        let aux_polynomials = &jolt.r1cs.aux;
        match self {
            JoltR1CSInputs::Bytecode_A => &jolt.bytecode.a_read_write,
            JoltR1CSInputs::Bytecode_ELFAddress => &jolt.bytecode.v_read_write[0],
            JoltR1CSInputs::Bytecode_Bitflags => &jolt.bytecode.v_read_write[1],
            JoltR1CSInputs::Bytecode_RD => &jolt.bytecode.v_read_write[2],
            JoltR1CSInputs::Bytecode_RS1 => &jolt.bytecode.v_read_write[3],
            JoltR1CSInputs::Bytecode_RS2 => &jolt.bytecode.v_read_write[4],
            JoltR1CSInputs::Bytecode_Imm => &jolt.bytecode.v_read_write[5],
            JoltR1CSInputs::RAM_Address => &jolt.read_write_memory.a_ram,
            JoltR1CSInputs::RS1_Read => &jolt.read_write_memory.v_read_rs1,
            JoltR1CSInputs::RS2_Read => &jolt.read_write_memory.v_read_rs2,
            JoltR1CSInputs::RD_Read => &jolt.read_write_memory.v_read_rd,
            JoltR1CSInputs::RAM_Read => &jolt.read_write_memory.v_read_ram,
            JoltR1CSInputs::RD_Write => &jolt.read_write_memory.v_write_rd,
            JoltR1CSInputs::RAM_Write => &jolt.read_write_memory.v_write_ram,
            JoltR1CSInputs::ChunksQuery(i) => &jolt.instruction_lookups.dim[*i],
            JoltR1CSInputs::LookupOutput => &jolt.instruction_lookups.lookup_outputs,
            JoltR1CSInputs::ChunksX(i) => &jolt.r1cs.chunks_x[*i],
            JoltR1CSInputs::ChunksY(i) => &jolt.r1cs.chunks_y[*i],
            JoltR1CSInputs::OpFlags(i) => &jolt.r1cs.circuit_flags[*i as usize],
            JoltR1CSInputs::InstructionFlags(i) => {
                &jolt.instruction_lookups.instruction_flags[RV32I::enum_index(i)]
            }
            Self::Aux(aux) => match aux {
                AuxVariable::LeftLookupOperand => &aux_polynomials.left_lookup_operand,
                AuxVariable::RightLookupOperand => &aux_polynomials.right_lookup_operand,
                AuxVariable::Product => &aux_polynomials.product,
                AuxVariable::RelevantYChunk(i) => &aux_polynomials.relevant_y_chunks[*i],
                AuxVariable::WriteLookupOutputToRD => &aux_polynomials.write_lookup_output_to_rd,
                AuxVariable::WritePCtoRD => &aux_polynomials.write_pc_to_rd,
                AuxVariable::NextPCJump => &aux_polynomials.next_pc_jump,
                AuxVariable::ShouldBranch => &aux_polynomials.should_branch,
                AuxVariable::NextPC => &aux_polynomials.next_pc,
            },
        }
    }

    fn get_ref_mut<'a, T: CanonicalSerialize + CanonicalDeserialize + Sync>(
        &self,
        jolt: &'a mut JoltStuff<T>,
    ) -> &'a mut T {
        let aux_polynomials = &mut jolt.r1cs.aux;
        match self {
            Self::Aux(aux) => match aux {
                AuxVariable::LeftLookupOperand => &mut aux_polynomials.left_lookup_operand,
                AuxVariable::RightLookupOperand => &mut aux_polynomials.right_lookup_operand,
                AuxVariable::Product => &mut aux_polynomials.product,
                AuxVariable::RelevantYChunk(i) => &mut aux_polynomials.relevant_y_chunks[*i],
                AuxVariable::WriteLookupOutputToRD => {
                    &mut aux_polynomials.write_lookup_output_to_rd
                }
                AuxVariable::WritePCtoRD => &mut aux_polynomials.write_pc_to_rd,
                AuxVariable::NextPCJump => &mut aux_polynomials.next_pc_jump,
                AuxVariable::ShouldBranch => &mut aux_polynomials.should_branch,
                AuxVariable::NextPC => &mut aux_polynomials.next_pc,
            },
            _ => panic!("get_ref_mut should only be invoked when computing aux polynomials"),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::jolt::vm::JoltPolynomials;

    use super::*;

    #[test]
    fn from_index_to_index() {
        const C: usize = 4;
        for i in 0..JoltR1CSInputs::num_inputs::<C>() {
            assert_eq!(i, JoltR1CSInputs::from_index::<C>(i).to_index::<C>());
        }
        for var in JoltR1CSInputs::flatten::<C>() {
            assert_eq!(
                var,
                JoltR1CSInputs::from_index::<C>(JoltR1CSInputs::to_index::<C>(&var))
            );
        }
    }

    #[test]
    fn get_ref() {
        const C: usize = 4;
        let mut jolt_polys: JoltPolynomials<Fr> = JoltPolynomials::default();
        jolt_polys.r1cs = R1CSPolynomials::initialize(&C);

        for aux in AuxVariable::iter().flat_map(|aux| match aux {
            AuxVariable::RelevantYChunk(_) => (0..C)
                .into_iter()
                .map(|i| JoltR1CSInputs::Aux(AuxVariable::RelevantYChunk(i)))
                .collect(),
            _ => vec![JoltR1CSInputs::Aux(aux)],
        }) {
            let ref_ptr = aux.get_ref(&jolt_polys) as *const MultilinearPolynomial<Fr>;
            let ref_mut_ptr = aux.get_ref_mut(&mut jolt_polys) as *const MultilinearPolynomial<Fr>;
            assert_eq!(ref_ptr, ref_mut_ptr, "Pointer mismatch for {:?}", aux);
        }
    }

    #[test]
    fn r1cs_stuff_ordering() {
        const C: usize = 4;
        R1CSOpenings::<Fr>::test_ordering_consistency(&C);
    }
}
