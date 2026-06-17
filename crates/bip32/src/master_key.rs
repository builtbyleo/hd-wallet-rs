use std::fmt;

use bip39::Seed;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;

pub struct MasterExtPrivKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

type HmacSha512 = Hmac<Sha512>;

impl MasterExtPrivKey {
    #[must_use]
    fn new(seed: Seed) -> Self {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();

        mac.update(seed.as_bytes());

        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);

        chain_code.copy_from_slice(&result[32..]);

        Self { key, chain_code }
    }
}
