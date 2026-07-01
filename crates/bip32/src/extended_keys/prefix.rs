use std::fmt::{Display, Formatter, Result};

pub enum Prefix {
    XPub,
    XPrv,
}

impl Prefix {
    pub const fn to_bytes(self) -> [u8; 4] {
        match self {
            Self::XPub => 0x0488B21Eu32.to_be_bytes(),
            Self::XPrv => 0x0488ADE4u32.to_be_bytes(),
        }
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::XPub => write!(f, "xpub"),
            Self::XPrv => write!(f, "xprv"),
        }
    }
}
