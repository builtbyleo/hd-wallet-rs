use k256::ecdsa::VerifyingKey;

use crate::extended_keys::{ExtPrivKey, ExtendedKeyAttrs};

pub struct ExtPubKey {
    pub_key: VerifyingKey,
    attributes: ExtendedKeyAttrs,
}

impl From<&ExtPrivKey> for ExtPubKey {
    fn from(xpriv: &ExtPrivKey) -> Self {
        let pub_key = VerifyingKey::from(xpriv.private_key());
        Self {
            pub_key,
            attributes: xpriv.attributes().clone(),
        }
    }
}

impl ExtPubKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.pub_key
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("expected SEC1 key")
    }
}
