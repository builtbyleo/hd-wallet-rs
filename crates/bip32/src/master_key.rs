use bip39::Seed;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;

use crate::attributes::ExtendedKeyAttrs;

pub struct MasterExtPrivKey {
    private_key: [u8; 32],
    attributes: ExtendedKeyAttrs,
}

type HmacSha512 = Hmac<Sha512>;

/// Derivation domain separator for BIP39 keys.
const BIP39_DOMAIN_SEPARATOR: &[u8; 12] = b"Bitcoin seed";

impl MasterExtPrivKey {
    #[must_use]
    fn new(seed: Seed) -> Self {
        // TODO: check seed len
        let mut mac = HmacSha512::new_from_slice(BIP39_DOMAIN_SEPARATOR).unwrap();

        mac.update(seed.as_bytes());

        let result = mac.finalize().into_bytes();

        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];

        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        let attributes = ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code,
        };

        Self {
            private_key,
            attributes,
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn known_ext_priv_key_from_known_seed() {
        todo!();
    }
}
