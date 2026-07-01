mod attributes;
mod errors;
mod prefix;
mod private_key;
mod public_key;

pub use attributes::{ChildNumber, ExtendedKeyAttrs};
pub use private_key::ExtPrivKey;
pub use public_key::ExtPubKey;

use hmac::Hmac;
use sha2::Sha512;

pub const KEY_SIZE: usize = 32;

pub const BYTE_SIZE: usize = 78;

pub const MAX_BASE58_SIZE: usize = 112;

type HmacSha512 = Hmac<Sha512>;
