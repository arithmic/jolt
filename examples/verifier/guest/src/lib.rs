#![cfg_attr(feature = "guest", no_std)]

use jolt::{
    tracer::JoltDevice, Jolt, JoltField, JoltProof, JoltVerifierPreprocessing, RV32IJoltVM, F, PCS,
};
use jolt_core::poly::commitment::commitment_scheme::CommitmentScheme;
#[cfg(test)]
use jolt_core::poly::commitment::dory::DoryGlobals;
use jolt_core::{
    jolt::vm::{rv32i_vm::WORD_SIZE, ProverDebugInfo},
    poly::opening_proof::VerifierOpeningAccumulator,
    r1cs::{
        constraints::{JoltRV32IMConstraints, R1CSConstraints},
        spartan::UniformSpartanProof,
    },
    utils::{errors::ProofVerifyError, transcript::Transcript},
};

// Fix this #[jolt::provable]
// #[jolt::provable]
fn verify<const WORD_SIZE: usize, F, PCS, ProofTranscript>(
    preprocessing: JoltVerifierPreprocessing<F, PCS, ProofTranscript>,
    proof: JoltProof<WORD_SIZE, F, PCS, ProofTranscript>,
    mut program_io: JoltDevice,
    _debug_info: Option<ProverDebugInfo<F, ProofTranscript, PCS>>,
) -> Result<(), ProofVerifyError>
where
    F: JoltField,
    PCS: CommitmentScheme<ProofTranscript, Field = F>,
    ProofTranscript: Transcript,
{
    let mut transcript = ProofTranscript::new(b"Jolt transcript");
    let mut opening_accumulator: VerifierOpeningAccumulator<F, PCS, ProofTranscript> =
        VerifierOpeningAccumulator::new();
    // truncate trailing zeros on device outputs
    program_io.outputs.truncate(
        program_io
            .outputs
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |pos| pos + 1),
    );


    #[cfg(test)]
    {
        if let Some(debug_info) = _debug_info {
             transcript.compare_to(debug_info.transcript);
            opening_accumulator
                .compare_to(debug_info.opening_accumulator, &debug_info.prover_setup);
        }
    }

    #[cfg(test)]
    let K = [
        preprocessing.shared.bytecode.code_size,
        proof.ram.K,
        1 << 16, // K for instruction lookups Shout
    ]
    .into_iter()
    .max()
    .unwrap();
    #[cfg(test)]
    let T = proof.trace_length.next_power_of_two();
    // Need to initialize globals because the verifier computes commitments
    // in `VerifierOpeningAccumulator::append` inside of a `#[cfg(test)]` block
    #[cfg(test)]
    let _guard = DoryGlobals::initialize(K, T);

    <RV32IJoltVM as Jolt<32, F, PCS, ProofTranscript>>::fiat_shamir_preamble(
        &mut transcript,
        &program_io,
        &preprocessing.shared.memory_layout,
        proof.trace_length,
        proof.ram.K,
    );

    for commitment in proof.commitments.commitments.iter() {
        transcript.append_serializable(commitment);
    }

    // Regenerate the uniform Spartan key
    let padded_trace_length = proof.trace_length.next_power_of_two();
    let r1cs_builder =
        <JoltRV32IMConstraints as R1CSConstraints<F>>::construct_constraints(padded_trace_length);
    let spartan_key =
        UniformSpartanProof::<F, ProofTranscript>::setup(&r1cs_builder, padded_trace_length);
    transcript.append_scalar(&spartan_key.vk_digest);

    proof
        .r1cs
        .verify(
            &spartan_key,
            &proof.commitments,
            &mut opening_accumulator,
            &mut transcript,
        )
        .map_err(|e| ProofVerifyError::SpartanError(e.to_string()))?;
    proof.instruction_lookups.verify(
        &proof.commitments,
        &mut opening_accumulator,
        &mut transcript,
    )?;
    proof.registers.verify(
        &proof.commitments,
        padded_trace_length,
        &mut opening_accumulator,
        &mut transcript,
    )?;
    proof.ram.verify(
        padded_trace_length,
        &preprocessing.shared.ram,
        &proof.commitments,
        &program_io,
        &mut transcript,
        &mut opening_accumulator,
    )?;
    proof.bytecode.verify(
        &preprocessing.shared.bytecode,
        &proof.commitments,
        padded_trace_length,
        &mut transcript,
        &mut opening_accumulator,
    )?;

    // Batch-verify all openings
    opening_accumulator.reduce_and_verify(
        &preprocessing.generators,
        &proof.opening_proof,
        &mut transcript,
    )?;

    Ok(())
}
