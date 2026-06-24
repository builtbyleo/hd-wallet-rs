#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Opaque crypto errors
    Crypto,
    /// Max Depth reached
    MaxDepth,
    /// Invalid Child Number Index
    InvalidIndex,
}

impl From<k256::ecdsa::Error> for Error {
    fn from(_: k256::ecdsa::Error) -> Error {
        Error::Crypto
    }
}

impl From<sha2::digest::InvalidLength> for Error {
    fn from(_: sha2::digest::InvalidLength) -> Error {
        Error::Crypto
    }
}
