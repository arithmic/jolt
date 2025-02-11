use core::fmt;

use super::{non_native::Fqq, sum_check::SumcheckInstanceProofCircom};

// use crate::{helper_non_native::Fqq, helper_sum_check::SumcheckInstanceProofCircom};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchedGrandProductLayerProofCircom{
    pub proof: SumcheckInstanceProofCircom,
    pub left_claim: Fqq,
    pub right_claim: Fqq,
}

impl fmt::Debug for BatchedGrandProductLayerProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "proof": {:?},
                "left_claim": {:?},
                "right_claim": {:?}
                }}"#,
            self.proof, self.left_claim, self.right_claim
        )
    }
}



#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchedGrandProductProofCircom{
    pub gkr_layers: Vec<BatchedGrandProductLayerProofCircom>
}

impl fmt::Debug for BatchedGrandProductProofCircom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "gkr_layers": {:?}
                }}"#,
            self.gkr_layers,
        )
    }
}



pub struct VecFqq{
    pub state: Vec<Fqq>
}
impl fmt::Debug for VecFqq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"[
            "{:?}"
            ]"#,
            self.state
        )
    }
}