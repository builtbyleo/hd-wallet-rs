use k256::ecdsa::VerifyingKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::extended_keys::{ExtPrivKey, ExtendedKeyAttrs, KEY_SIZE};

pub struct ExtPubKey {
    public_key: VerifyingKey,
    attributes: ExtendedKeyAttrs,
}

impl From<&ExtPrivKey> for ExtPubKey {
    fn from(xpriv: &ExtPrivKey) -> Self {
        let pub_key = VerifyingKey::from(xpriv.private_key());
        Self {
            public_key: pub_key,
            attributes: xpriv.attributes().clone(),
        }
    }
}

impl ExtPubKey {
    pub fn to_bytes(&self) -> [u8; KEY_SIZE + 1] {
        self.public_key
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("expected SEC1 key")
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let pub_hash = Ripemd160::digest(Sha256::digest(self.to_bytes()));
        pub_hash[..4].try_into().expect("pub hash truncated")
    }
}
