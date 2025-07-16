
use ark_bn254::Fr;
use jolt_core::jolt::vm::rv32i_vm::fib_e2e_for_riscv;
use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
use jolt_core::utils::transcript::KeccakTranscript;


fn main() {
    fib_e2e_for_riscv::<Fr, DoryCommitmentScheme<KeccakTranscript>, KeccakTranscript>();
}

// fn main() {
//     // Collect the command-line arguments as a Vec<String>
//     // let args: Vec<String> = env::args().collect();

//     // // Check if the user passed an argument
//     // if args.len() < 2 {
//     //     eprintln!("Usage: {} <number of steps>", args[0]);
//     //     std::process::exit(1);
//     // }

//     // // Parse the first argument as a u32
//     // let steps: u32 = args[1].parse().expect("Please enter a valid number");
//     let steps = 10;
//     let mut a = 0;
//     let mut b = 1;
//     let mut temp;

//     for _ in 0..steps {
//         temp = b;
//         b = a + b;
//         a = temp;
//     }

//     println!("Result: {}", b);
// }
