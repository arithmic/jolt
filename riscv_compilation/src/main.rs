
use ark_bn254::Fr;
use jolt_core::jolt::vm::rv32i_vm::fib_e2e_for_riscv;
use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
use jolt_core::utils::transcript::KeccakTranscript;


fn main() {
    fib_e2e_for_riscv::<Fr, DoryCommitmentScheme<KeccakTranscript>, KeccakTranscript>();
}