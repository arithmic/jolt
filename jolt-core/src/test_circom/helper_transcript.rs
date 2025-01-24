use core::fmt;

use ark_bn254::{Fr as Scalar, Fq as Fp};
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestTranscript{
    pub state: Fp,
    pub nrounds: Fp,
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

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]

pub struct G1AffineFormTest{
    pub x: Fp,
    pub y: Fp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]

pub struct G1AffineFormTestArray{
    points: [G1AffineFormTest; SCALAR_LEN]
}

impl fmt::Debug for G1AffineFormTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "x": "{}",
            "y": "{}"
            }}"#,
            self.x, self.y
        )
    }
}
