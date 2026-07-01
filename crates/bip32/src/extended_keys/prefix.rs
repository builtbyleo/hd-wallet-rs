use std::fmt::{Display, Formatter, Result};

#[allow(non_camel_case_types)]
pub enum Prefix {
    xpub,
    xpriv,
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::xpub => write!(f, "xpub"),
            Self::xpriv => write!(f, "xpriv"),
        }
    }
}
