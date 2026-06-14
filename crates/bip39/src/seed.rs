use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::fmt;

use crate::mnemonic::Mnemonic;

#[derive(Clone)]
pub struct Seed {
    bytes: Vec<u8>,
}

const ROUNDS: u32 = 2048;

impl Seed {
    pub fn new(mnemonic: &Mnemonic, passphrase: Option<&str>) -> Self {
        let salt = format!("mnemonic{}", passphrase.unwrap_or(""));

        let mut buff = [0u8; 64];

        pbkdf2_hmac::<Sha512>(
            mnemonic.phrase().as_bytes(),
            salt.as_bytes(),
            ROUNDS,
            &mut buff,
        );

        Self {
            bytes: buff.to_vec(),
        }
    }
}

impl fmt::LowerHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}
