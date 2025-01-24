use core::fmt;

use super::{helper_hyperkzg::HyperKZGProofCircom, helper_non_native::Fqq, helper_sum_check::SumcheckInstanceProofCircom};

// use crate::{helper_hyperkzg::HyperKZGProofCircom, helper_non_native::Fqq, helper_sum_check::SumcheckInstanceProofCircom};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReducedOpeningProofCircom{
    pub sumcheck_proof: SumcheckInstanceProofCircom,
    pub sumcheck_claims: Vec<Fqq>,
    pub joint_opening_proof: HyperKZGProofCircom
}

impl fmt::Debug for ReducedOpeningProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "sumcheck_proof": {:?},
            "sumcheck_claims": {:?},
            "joint_opening_proof": {:?}
            }}"#,
            self.sumcheck_proof, self.sumcheck_claims, self.joint_opening_proof
        )
    }
}
