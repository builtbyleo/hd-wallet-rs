use bip39::Seed;
use hmac::{KeyInit, Mac};
use k256::{NonZeroScalar, ecdsa::SigningKey};
use std::fmt::{self, Display};

use crate::extended_keys::{
    BYTE_SIZE, ChildNumber, ExtPubKey, ExtendedKeyAttrs, HmacSha512, KEY_SIZE, errors::Error,
    prefix::Prefix,
};

pub struct ExtPrivKey {
    private_key: SigningKey,
    attributes: ExtendedKeyAttrs,
}

/// Derivation domain separator for BIP39 keys.
const BIP32_DOMAIN_SEPARATOR: &[u8; 12] = b"Bitcoin seed";

impl ExtPrivKey {
    pub fn new(seed: Seed) -> Result<Self, Error> {
        let mut mac = HmacSha512::new_from_slice(BIP32_DOMAIN_SEPARATOR)?;

        mac.update(seed.as_bytes());

        let result = mac.finalize().into_bytes();
        let (private_key, chain_code) = result.split_at(KEY_SIZE);

        let private_key = SigningKey::from_slice(private_key)?;

        let attributes = ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::normal(0)?,
            chain_code: chain_code.try_into()?,
        };

        Ok(Self {
            private_key,
            attributes,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> ExtPubKey {
        self.into()
    }

    #[must_use]
    pub fn private_key(&self) -> &SigningKey {
        &self.private_key
    }

    #[must_use]
    pub fn attributes(&self) -> &ExtendedKeyAttrs {
        &self.attributes
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes().into()
    }

    /// Default derivation is to derive hardened child
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self, Error> {
        if !child_number.is_hardened() {
            return Err(Error::InvalidIndex);
        }

        self.derive_with(child_number, |mac, this| {
            mac.update(&[0u8]);
            mac.update(&this.to_bytes());
            Ok(())
        })
    }

    pub fn derive_normal_child(&self, child_number: ChildNumber) -> Result<Self, Error> {
        if child_number.is_hardened() {
            return Err(Error::InvalidIndex);
        }

        self.derive_with(child_number, |mac, this| {
            mac.update(&this.public_key().to_bytes());
            Ok(())
        })
    }

    fn derive_with<F>(&self, child_number: ChildNumber, update_mac: F) -> Result<Self, Error>
    where
        F: FnOnce(&mut HmacSha512, &Self) -> Result<(), Error>,
    {
        let depth = self
            .attributes
            .depth
            .checked_add(1)
            .ok_or(Error::MaxDepth)?;

        let mut mac = HmacSha512::new_from_slice(&self.attributes.chain_code)?;

        update_mac(&mut mac, self)?;
        mac.update(&child_number.to_bytes());

        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[..KEY_SIZE].try_into().map_err(|_| Error::Crypto)?;
        let chain_code: [u8; 32] = result[KEY_SIZE..].try_into().map_err(|_| Error::Crypto)?;

        let private_key = self.derive_private_key(il)?;

        let attributes = ExtendedKeyAttrs {
            parent_fingerprint: self.public_key().fingerprint(),
            child_number,
            chain_code,
            depth,
        };

        Ok(Self {
            private_key,
            attributes,
        })
    }

    fn derive_private_key(&self, il: [u8; 32]) -> Result<SigningKey, Error> {
        let child_scalar = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr(il.into()))
            .ok_or(Error::Crypto)?;

        let derived_scalar = self.private_key.as_nonzero_scalar().as_ref() + child_scalar.as_ref();

        let private_key = Option::<NonZeroScalar>::from(NonZeroScalar::new(derived_scalar))
            .ok_or(Error::Crypto)?;

        Ok(SigningKey::from(private_key))
    }

    fn encode(&self) -> String {
        let mut bytes = [0u8; BYTE_SIZE];
        bytes[..4].copy_from_slice(&Prefix::XPrv.to_bytes());
        bytes[4] = self.attributes.depth;
        bytes[5..9].copy_from_slice(&self.attributes.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.attributes.child_number.to_bytes());
        bytes[13..45].copy_from_slice(&self.attributes.chain_code);
        bytes[45] = 0x00;
        bytes[46..78].copy_from_slice(&self.private_key.to_bytes());
        let base58 = bs58::encode(&bytes).with_check();
        base58.into_string()
    }
}

impl Display for ExtPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

#[cfg(test)]
mod test {
    use bip39::Seed;

    use crate::extended_keys::{ChildNumber, private_key::ExtPrivKey};

    const SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    const EXPECTED_MASTER_PRIV_KEY: &str =
        "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67";

    const EXPECTED_MASTER_CHAIN_CODE: &str =
        "7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e";

    fn known_seed() -> Seed {
        Seed::from_hex(SEED_HEX).unwrap()
    }

    fn known_master_priv_key() -> ExtPrivKey {
        ExtPrivKey::new(known_seed()).unwrap()
    }

    fn assert_ext_priv_key_matches(
        key: &ExtPrivKey,
        expected_private_key: &str,
        expected_chain_code: &str,
    ) {
        assert_eq!(
            hex::encode(key.private_key.to_bytes()),
            expected_private_key,
            "private key mismatch",
        );

        let expected_chain_code: [u8; 32] = hex::decode(expected_chain_code)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(
            key.attributes.chain_code, expected_chain_code,
            "chain code mismatch",
        );
    }

    #[test]
    fn known_ext_priv_key_from_known_seed() {
        let master_priv_key = known_master_priv_key();

        assert_ext_priv_key_matches(
            &master_priv_key,
            EXPECTED_MASTER_PRIV_KEY,
            EXPECTED_MASTER_CHAIN_CODE,
        );
    }

    #[test]
    fn known_child_from_known_master_key() {
        let master_priv_key = known_master_priv_key();

        let child = master_priv_key
            .derive_child(ChildNumber::hardened(0).unwrap())
            .unwrap();

        let child_private_key = hex::encode(child.private_key.to_bytes());
        let expected_child = "c08cf331996482c06db3d259ff99be4bf7083824d53185e33191ee7ceb2bf96f";

        assert_eq!(
            child_private_key, expected_child,
            "child private key mismatch"
        );
    }
}
