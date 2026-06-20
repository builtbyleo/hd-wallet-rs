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
const BIP32_DOMAIN_SEPARATOR: &[u8; 12] = b"Bitcoin seed";

impl MasterExtPrivKey {
    #[must_use]
    fn new(seed: Seed) -> Self {
        // TODO: check seed len
        let mut mac = HmacSha512::new_from_slice(BIP32_DOMAIN_SEPARATOR).unwrap();

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
    use bip39::Seed;

    use crate::master_key::MasterExtPrivKey;

    #[test]
    fn known_ext_priv_key_from_known_seed() {
        let known_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

        let seed = Seed::from_hex(known_seed).unwrap();

        let master_priv_key = MasterExtPrivKey::new(seed);

        let private_key = master_priv_key.private_key;
        let chain_code = master_priv_key.attributes.chain_code;

        let expected_priv_key: [u8; 32] =
            hex::decode("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67")
                .unwrap()
                .try_into()
                .unwrap();

        assert_eq!(private_key, expected_priv_key);

        let expected_chain_code: [u8; 32] =
            hex::decode("7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e")
                .unwrap()
                .try_into()
                .unwrap();

        assert_eq!(chain_code, expected_chain_code);
    }
}
