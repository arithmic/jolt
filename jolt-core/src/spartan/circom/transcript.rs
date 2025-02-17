use core::fmt;

use ark_grumpkin::{Fr as GrumpkinScalar, Fq as GrumpkinBase, Projective};

use crate::utils::poseidon_transcript::{GrumpkinPoseidonTranscript, PoseidonTranscript};
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestTranscript{
    pub state: GrumpkinBase,
    pub nrounds: GrumpkinBase,
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

pub fn convert_transcript_to_circom(transcript: GrumpkinPoseidonTranscript<GrumpkinBase>) -> TestTranscript {
    TestTranscript {
        state: GrumpkinBase::from(transcript.state.state[1]),
        nrounds: GrumpkinBase::from(transcript.n_rounds),
    }
}