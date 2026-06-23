mod attributes;
mod errors;
mod private_key;
mod public_key;

pub use attributes::{ChildNumber, ExtendedKeyAttrs};
pub use private_key::ExtPrivKey;
pub use public_key::ExtPubKey;

pub const KEY_SIZE: usize = 32;
