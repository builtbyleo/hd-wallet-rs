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
    #[must_use]
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
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02X}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{Mnemonic, seed::Seed};

    #[test]
    fn known_seed_from_known_mnemonic() {
        let known_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let known_mnemonic = Mnemonic {
            words: known_words.to_owned(),
        };

        let seed = format!("{:x}", Seed::new(&known_mnemonic, None));

        let expected_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

        assert_eq!(seed, expected_seed);
    }
}
