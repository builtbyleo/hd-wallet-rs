use crate::extended_keys::errors::Error;

// Max::u31 = 2^31
const HARDENED_OFFSET: u32 = 1 << 31;

#[derive(Clone, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
    pub fn normal(n: u32) -> Result<Self, Error> {
        if n >= HARDENED_OFFSET {
            return Err(Error::InvalidIndex);
        }

        Ok(Self(n))
    }

    pub fn hardened(n: u32) -> Result<Self, Error> {
        if n >= HARDENED_OFFSET {
            return Err(Error::InvalidIndex);
        }

        Ok(Self(n + HARDENED_OFFSET))
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
