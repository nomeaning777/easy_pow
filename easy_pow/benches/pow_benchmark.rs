use criterion::{criterion_group, criterion_main, Criterion};
use easy_pow::{search, Hash, HashOutput, PowSearchParameters, ThreadConfig};

pub fn bench_hash_function_with_16bit_prefix_zero<H: Hash>(mut characters: Vec<Vec<u8>>) {
    for i in 0..10 {
        characters[i].clear();
        characters[i].push(rand::random());
    }
    let target_hash = H::Output::zero();
    let mut target_hash_mask = H::Output::zero();
    {
        let target_hash_mask = target_hash_mask.as_slice_mut();
        target_hash_mask[0] = 0xff;
        target_hash_mask[1] = 0xff;
    }

    let search_params = PowSearchParameters::<H> {
        target_hash,
        target_hash_mask,
        plaintext_character_map: characters,
    };
    let result = search(search_params, &ThreadConfig::default());
    match result {
        easy_pow::SearchResult::Found(result) => {
            let digest = H::hash(&result);
            let digest = digest.as_slice();
            assert_eq!(digest[0], 0);
            assert_eq!(digest[1], 0);
        }
        easy_pow::SearchResult::NotFound => {
            panic!("Not found")
        }
        _ => {
            panic!("Error")
        }
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let characters = vec![vec![b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9']; 30];
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_md5_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Md5>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_md5_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Md5>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha224_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha224>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha224_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha224>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha1_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha1>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha1_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha1>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha224_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha224>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha224_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha224>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha256_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha256>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha256_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha256>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha384_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha384>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha384_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha384>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-openssl")]
    c.bench_function("openssl_sha512_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::openssl::Sha512>(
                characters.clone(),
            );
        })
    });
    #[cfg(feature = "backend-rust-crypto")]
    c.bench_function("rust_crypto_sha512_16bit_zero_prefix", |b| {
        b.iter(|| {
            bench_hash_function_with_16bit_prefix_zero::<easy_pow::rust_crypto::Sha512>(
                characters.clone(),
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
