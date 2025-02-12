use core::fmt;

use super::{link_joltstuff::JoltStuffCircomLink, link_opening_combiners::{HyperKzgVerifierAdviceCircom, OpeningCombinersCircom}};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkingStuff2CircomLink{
    pub commitments: JoltStuffCircomLink,
    pub openingcombiners: OpeningCombinersCircom,
    pub hyperkzgverifieradvice: HyperKzgVerifierAdviceCircom
}


impl fmt::Debug for LinkingStuff2CircomLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
                "commitments": {:?},
                "openingcombiners": {:?},
                "hyperkzgverifieradvice": {:?}
            }}"#,
            self.commitments, self.openingcombiners, self.hyperkzgverifieradvice
        )
    }
}