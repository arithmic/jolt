use std::cmp::min;
use std::fmt;
use std::str::FromStr;
use ark_bn254::Fr as Scalar;
use ark_bn254::Fq as Fp;
use ark_ff::AdditiveGroup;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use num_bigint::BigUint;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fqq{
    // pub element: Scalar,
    pub limbs: [Fp; 3],
}

pub fn convert_from_3_limbs(limbs: Vec<Fp>) -> Scalar {
    let r = Scalar::from(BigUint::from(limbs[0].into_bigint()))
    + Scalar::from(2u8).pow([(125) as u64, 0, 0, 0]) * Scalar::from(limbs[1].into_bigint())
    + Scalar::from(2u8).pow([(250) as u64, 0, 0, 0]) * Scalar::from(limbs[2].into_bigint());
    r
}

pub fn convert_to_3_limbs(r: Scalar) -> [Fp; 3] {
    let mut limbs = [Fp::ZERO; 3];

    let mask = BigUint::from((1u128 << 125) - 1);

    limbs[0] = Fp::from(BigUint::from(r.into_bigint()) & mask.clone());

    limbs[1] = Fp::from((BigUint::from(r.into_bigint()) >> 125) & mask.clone());

    limbs[2] = Fp::from((BigUint::from(r.into_bigint()) >> 250) & mask.clone());

    limbs
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FqLimb{
    pub limbs: [Fp; 3],
}

impl fmt::Debug for Fqq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                            "limbs": ["{}", "{}", "{}"]
                        }}"#,
            &self.limbs[0], &self.limbs[1].to_string(), &self.limbs[2].to_string()
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytecodeCombinersCircom{
    pub rho: [Fqq; 2]
}

impl fmt::Debug for BytecodeCombinersCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                     "rho": {:?}
                }}"#,
            self.rho
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstructionLookupCombinersCircom{
    pub rho: [Fqq; 3]
}


impl fmt::Debug for InstructionLookupCombinersCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                     "rho": {:?}
                }}"#,
            self.rho
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadWriteOutputTimestampCombinersCircom {
    pub rho:  [Fqq; 4]
}


impl fmt::Debug for ReadWriteOutputTimestampCombinersCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                     "rho": {:?}
                }}"#,
            self.rho
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpartanCombinersCircom {
    pub rho:  Fqq
}


impl fmt::Debug for SpartanCombinersCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                     "rho": {:?}
                }}"#,
            self.rho
        )
    }
}


#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OpeningCombinersCircom{
    pub bytecodecombiners: BytecodeCombinersCircom,
    pub instructionlookupcombiners: InstructionLookupCombinersCircom,
    pub readwriteoutputtimestampcombiners: ReadWriteOutputTimestampCombinersCircom,
    pub spartancombiners: SpartanCombinersCircom,
    pub coefficient: Fqq
}

impl fmt::Debug for OpeningCombinersCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "bytecodecombiners": {:?},
                "instructionlookupcombiners": {:?},
                "readwriteoutputtimestampcombiners": {:?},
                "spartancombiners": {:?},
                "coefficient": {:?}
            }}"#,
            self.bytecodecombiners, self.instructionlookupcombiners, self.readwriteoutputtimestampcombiners, self.spartancombiners, self.coefficient
        )
    }
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HyperKzgVerifierAdviceCircom{
    pub r: Fqq,
    pub d_0: Fqq,
    pub v: Fqq,
    pub q_power: Fqq
}

impl fmt::Debug for HyperKzgVerifierAdviceCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "r": {:?},
                "d_0": {:?},
                "v": {:?},
                "q_power": {:?}
            }}"#,
            self.r, self.d_0, self.v, self.q_power
        )
    }
}

