use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid hash type")]
pub struct InvalidHashTypeError {
    _priv: (),
}

impl InvalidHashTypeError {
    fn new() -> Self {
        Self { _priv: () }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for HashType {
    type Err = InvalidHashTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha224" => Ok(Self::Sha224),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            _ => Err(InvalidHashTypeError::new()),
        }
    }
}
