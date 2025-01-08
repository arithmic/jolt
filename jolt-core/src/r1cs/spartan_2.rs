use crate::{field::JoltField, jolt::vm::rv32i_vm::ProofTranscript, poly::commitment::commitment_scheme::CommitmentScheme};


pub struct SNARK<F: JoltField, PCS: CommitmentScheme<ProofTranscript, Field = F>>{
    r1cs_sat_proof: R1CSProof_new<F, PCS>,

}

// #[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct R1CSProof_new<F: JoltField, PCS: CommitmentScheme<ProofTranscript, Field = F>> {
  comm_vars: PCS::Commitment,
  sc_proof_phase1: ZKSumcheckInstanceProof<F, PCS>,
  claims_phase2: (PCS::Commitment, PCS::Commitment, PCS::Commitment, PCS::Commitment),
//   pok_claims_phase2: (KnowledgeProof<G>, ProductProof<G>),
//   proof_eq_sc_phase1: EqualityProof<G>,
//   sc_proof_phase2: ZKSumcheckInstanceProof<G>,
//   comm_vars_at_ry: G,
//   proof_eval_vars_at_ry: PolyEvalProof<G>,
//   proof_eq_sc_phase2: EqualityProof<G>,
}

pub struct ZKSumcheckInstanceProof<F: JoltField, PCS: CommitmentScheme<ProofTranscript, Field = F>> {
    comm_polys: Vec<PCS::Commitment>,
    comm_evals: Vec<PCS::Commitment>,

}

pub struct EqualityProof<F: JoltField, PCS: CommitmentScheme<ProofTranscript, Field = F>>{
    alpha: PCS::Commitment,
    z: F
}

