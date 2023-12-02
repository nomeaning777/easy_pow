use crate::Hash;
use md5::Digest;
pub use md5::Md5;
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512};

impl Hash for Md5 {
    type Output = [u8; 16];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 16] {
        let out = Md5::digest(bytes);
        let mut ret = [0u8; 16];
        ret.copy_from_slice(&out);
        ret
    }
}

impl Hash for Sha1 {
    type Output = [u8; 20];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 20] {
        let out = Sha1::digest(bytes);
        let mut ret = [0u8; 20];
        ret.copy_from_slice(&out);
        ret
    }
}

impl Hash for Sha224 {
    type Output = [u8; 28];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 28] {
        let out = Sha224::digest(bytes);
        let mut ret = [0u8; 28];
        ret.copy_from_slice(&out);
        ret
    }
}

impl Hash for Sha256 {
    type Output = [u8; 32];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 32] {
        let out = Sha256::digest(bytes);
        let mut ret = [0u8; 32];
        ret.copy_from_slice(&out);
        ret
    }
}

impl Hash for Sha384 {
    type Output = [u8; 48];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 48] {
        let out = Sha384::digest(bytes);
        let mut ret = [0u8; 48];
        ret.copy_from_slice(&out);
        ret
    }
}

impl Hash for Sha512 {
    type Output = [u8; 64];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 64] {
        let out = Sha512::digest(bytes);
        let mut ret = [0u8; 64];
        ret.copy_from_slice(&out);
        ret
    }
}
