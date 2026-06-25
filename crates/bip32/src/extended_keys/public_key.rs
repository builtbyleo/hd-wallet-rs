use hmac::{KeyInit, Mac};
use k256::ecdsa::VerifyingKey;
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        ff::PrimeField,
        group::Group,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::{
    ChildNumber,
    extended_keys::{ExtPrivKey, ExtendedKeyAttrs, HmacSha512, KEY_SIZE, errors::Error},
};

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
    pub fn new(xpriv: &ExtPrivKey) -> Self {
        xpriv.into()
    }

    pub fn attributes(&self) -> &ExtendedKeyAttrs {
        &self.attributes
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

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

    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self, Error> {
        if child_number.is_hardened() {
            return Err(Error::InvalidIndex);
        };

        let depth = self
            .attributes
            .depth
            .checked_add(1)
            .ok_or(Error::MaxDepth)?;

        let mut mac = HmacSha512::new_from_slice(&self.attributes.chain_code)?;
        mac.update(&self.to_bytes());
        mac.update(&child_number.to_bytes());

        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[..KEY_SIZE].try_into().map_err(|_| Error::Crypto)?;
        let chain_code: [u8; 32] = result[KEY_SIZE..].try_into().map_err(|_| Error::Crypto)?;

        let verifying_key = self.derive_pub_key(il)?;

        let attributes = ExtendedKeyAttrs {
            parent_fingerprint: self.fingerprint(),
            child_number,
            chain_code,
            depth,
        };

        Ok(Self {
            public_key: verifying_key,
            attributes,
        })
    }

    fn derive_pub_key(&self, il: [u8; 32]) -> Result<VerifyingKey, Error> {
        let il_scalar =
            Option::<Scalar>::from(Scalar::from_repr(il.into())).ok_or(Error::InvalidIndex)?;

        let parent_encoded =
            EncodedPoint::from_bytes(self.to_bytes()).map_err(|_| Error::Crypto)?;

        let parent_point =
            Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&parent_encoded))
                .ok_or(Error::Crypto)?;

        let child_point =
            ProjectivePoint::GENERATOR * il_scalar + ProjectivePoint::from(parent_point);

        if bool::from(child_point.is_identity()) {
            return Err(Error::InvalidIndex);
        }

        let child_affine = AffinePoint::from(child_point);

        let child_public_key = child_affine.to_encoded_point(true);
        let verifying_key = VerifyingKey::from_encoded_point(&child_public_key)?;
        Ok(verifying_key)
    }
}
