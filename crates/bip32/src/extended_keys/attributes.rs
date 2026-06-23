use crate::extended_keys::errors::Error;

// Max::u31 = 2^31
const HARDENED_OFFSET: u32 = 1 << 31;

#[derive(Clone, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
    pub fn normal(n: u32) -> Result<Self, Error> {
        match n {
            ..HARDENED_OFFSET => Ok(Self(n)),
            _ => Err(Error::InvalidRange),
        }
    }
    pub fn hardened(n: u32) -> Result<Self, Error> {
        match n {
            HARDENED_OFFSET.. => Ok(Self(n)),
            _ => Err(Error::InvalidRange),
        }
    }

    pub fn is_hardened(&self) -> bool {
        self.0 >= HARDENED_OFFSET
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedKeyAttrs {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: ChildNumber,
    pub chain_code: [u8; 32],
}
