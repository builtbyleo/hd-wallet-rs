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
