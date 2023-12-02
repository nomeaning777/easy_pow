use crate::Hash;

pub struct Md5 {}

impl Hash for Md5 {
    type Output = [u8; 16];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 16] {
        let out = openssl::hash::hash(openssl::hash::MessageDigest::md5(), bytes)
            .expect("failed to hash");
        let mut ret = [0u8; 16];
        ret.copy_from_slice(&out);
        ret
    }
}

pub struct Sha1 {}

impl Hash for Sha1 {
    type Output = [u8; 20];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 20] {
        openssl::sha::sha1(bytes)
    }
}

pub struct Sha224 {}

impl Hash for Sha224 {
    type Output = [u8; 28];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 28] {
        openssl::sha::sha224(bytes)
    }
}

pub struct Sha256 {}

impl Hash for Sha256 {
    type Output = [u8; 32];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 32] {
        openssl::sha::sha256(bytes)
    }
}

pub struct Sha384 {}

impl Hash for Sha384 {
    type Output = [u8; 48];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 48] {
        openssl::sha::sha384(bytes)
    }
}

pub struct Sha512 {}

impl Hash for Sha512 {
    type Output = [u8; 64];
    const PARALLEL_BLOCK_SIZE: usize = 4096;

    fn hash(bytes: &[u8]) -> [u8; 64] {
        openssl::sha::sha512(bytes)
    }
}
