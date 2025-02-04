use core::fmt;

use ark_bn254::{Bn254, Fq as Fp, Fr as Scalar};

use crate::utils::poseidon_transcript::PoseidonTranscript;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestTranscript{
    pub state: Scalar,
    pub nrounds: Scalar,
}

const SCALAR_LEN: usize = 2;

impl fmt::Debug for TestTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "state": "{}",
            "nRounds": "{}"
            }}"#,
            self.state, self.nrounds
        )
    }
}

// change it after fixing rust transcript
use ark_ff::PrimeField;
pub fn convert_transcript_to_circom(transcript: PoseidonTranscript<Fp>) -> TestTranscript {
    TestTranscript {
        state: Scalar::from(transcript.state.state[1].into_bigint()),
        nrounds: Scalar::from(transcript.n_rounds),
    }
}