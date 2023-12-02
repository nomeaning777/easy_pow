use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

#[cfg(feature = "backend-openssl")]
#[doc(hidden)]
pub mod openssl;
#[cfg(feature = "backend-rust-crypto")]
#[doc(hidden)]
pub mod rust_crypto;

mod hash_type;

#[cfg(feature = "backend-rust-crypto")]
pub use rust_crypto::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512};

#[cfg(all(not(feature = "backend-rust-crypto"), feature = "backend-openssl"))]
pub use openssl::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512};

pub use hash_type::{HashType, InvalidHashTypeError};

pub trait HashOutput: Sync + Send + Clone + Sized {
    const HASH_BYTES: usize;

    fn as_slice(&self) -> &[u8];
    fn as_slice_mut(&mut self) -> &mut [u8];
    fn from_slice(slice: &[u8]) -> Option<Self>;
    fn zero() -> Self;
}

impl<const N: usize> HashOutput for [u8; N] {
    const HASH_BYTES: usize = N;

    fn as_slice(&self) -> &[u8] {
        &self[..]
    }

    fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self[..]
    }

    fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == N {
            let mut ret = [0u8; N];
            ret.copy_from_slice(slice);
            Some(ret)
        } else {
            None
        }
    }

    fn zero() -> Self {
        [0u8; N]
    }
}

/// The trait representing the hash function used in Pow (Proof of Work)
pub trait Hash {
    /// Hash output type
    type Output: HashOutput;
    /// When executing in parallel, the maximum size for pushing to a task queue.
    const PARALLEL_BLOCK_SIZE: usize;

    /// The hash function
    fn hash(bytes: &[u8]) -> Self::Output;
}

#[derive(Debug, Clone)]
pub struct PowSearchParameters<H: Hash> {
    pub target_hash: H::Output,
    pub target_hash_mask: H::Output,

    pub plaintext_character_map: Vec<Vec<u8>>,
}

impl<H: Hash> PowSearchParameters<H> {
    #[inline]
    fn check_hash(&self, hash: &H::Output) -> bool {
        let hash = hash.as_slice();
        let target_hash = self.target_hash.as_slice();
        let target_hash_mask = self.target_hash_mask.as_slice();

        for i in 0..hash.len() {
            if (hash[i] & target_hash_mask[i]) != (target_hash[i] & target_hash_mask[i]) {
                return false;
            }
        }
        true
    }
}

struct PowSearcher<H: Hash> {
    to_search_thread: crossbeam::channel::Sender<(Vec<u8>, usize)>,
    from_search_thread: crossbeam::channel::Receiver<Vec<u8>>,

    parameter: Arc<PowSearchParameters<H>>,
    message_count: Vec<usize>,
    search_end: Arc<AtomicBool>,
}

struct PowSearcherWorker<H: Hash> {
    from_search_thread: crossbeam::channel::Receiver<(Vec<u8>, usize)>,
    to_search_thread: crossbeam::channel::Sender<Vec<u8>>,
    search_end: Arc<AtomicBool>,
    parameter: Arc<PowSearchParameters<H>>,
}

impl<H: Hash> PowSearcherWorker<H> {
    fn search(&self, current_plaintext: &mut Vec<u8>, pos: usize) -> Result<(), SearchError> {
        if pos == current_plaintext.len() {
            if self.parameter.check_hash(&H::hash(&current_plaintext)) {
                return Err(SearchError::Found(current_plaintext.clone()));
            }
            Ok(())
        } else {
            for &c in &self.parameter.plaintext_character_map[pos] {
                current_plaintext[pos] = c;
                self.search(current_plaintext, pos + 1)?;
                if self.search_end.load(Ordering::Relaxed) {
                    break;
                }
            }
            current_plaintext[pos] = 0;
            Ok(())
        }
    }

    fn search_thread(&self) {
        while let Ok((mut plaintext, pos)) = self.from_search_thread.recv() {
            match self.search(&mut plaintext, pos) {
                Ok(_) => {}
                Err(SearchError::Found(ret)) => {
                    let _ = self.to_search_thread.try_send(ret);
                    self.search_end.store(true, Ordering::Relaxed);
                }
                Err(SearchError::ThreadChannelError) => {
                    break;
                }
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum SearchError {
    #[error("Hash found")]
    Found(Vec<u8>),
    #[error("The thread channel is closed")]
    ThreadChannelError,
}

impl<H: Hash> PowSearcher<H> {
    fn search(&self, current_plaintext: &mut Vec<u8>, pos: usize) -> Result<(), SearchError> {
        if pos == current_plaintext.len() {
            if self.parameter.check_hash(&H::hash(&current_plaintext)) {
                return Err(SearchError::Found(current_plaintext.clone()));
            }
            Ok(())
        } else if self.message_count[pos] <= H::PARALLEL_BLOCK_SIZE {
            crossbeam::channel::select! {
                recv(self.from_search_thread) -> ret => {
                    match ret {
                        Ok(ret) => return Err(SearchError::Found(ret)),
                        Err(_) => {
                            eprintln!("Thread recv error!!!");
                            return Err(SearchError::ThreadChannelError);
                        }
                    }
                },
                send(self.to_search_thread, (current_plaintext.clone(), pos)) -> ret => {
                    if ret.is_err() {
                        eprintln!("Thread send error");
                        return Err(SearchError::ThreadChannelError);
                    }
                }
            };
            Ok(())
        } else {
            for &c in &self.parameter.plaintext_character_map[pos] {
                current_plaintext[pos] = c;
                self.search(current_plaintext, pos + 1)?;
                if self.search_end.load(Ordering::Relaxed) {
                    break;
                }
            }
            current_plaintext[pos] = 0;
            Ok(())
        }
    }

    fn run_search(self) -> Result<(), SearchError> {
        let mut plaintext = vec![0; self.parameter.plaintext_character_map.len()];
        self.search(&mut plaintext, 0)?;
        drop(self.to_search_thread);
        while let Ok(ret) = self.from_search_thread.recv() {
            return Err(SearchError::Found(ret));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadConfig {
    pub thread_count: Option<usize>,
    pub cancel: Option<Arc<AtomicBool>>,
}

pub enum SearchResult {
    Found(Vec<u8>),
    NotFound,
    UnexpectedError,
    InvalidTargetHashLength,
    InvalidTargetHashMaskLength,
}

pub fn search<H: Hash>(
    params: PowSearchParameters<H>,
    thread_config: &ThreadConfig,
) -> SearchResult {
    let thread_count = thread_config.thread_count.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|a| a.get())
            .unwrap_or(2)
    });
    let params = Arc::new(params);
    thread::scope(|s: &thread::Scope<'_, '_>| {
        let (from_main_thread_tx, from_main_thread_rx) = crossbeam::channel::bounded(thread_count);
        let (from_worker_thread_tx, from_worker_thread_rx) =
            crossbeam::channel::bounded(thread_count);
        let search_end = thread_config
            .cancel
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

        for _ in 0..thread_count {
            let worker = PowSearcherWorker {
                from_search_thread: from_worker_thread_rx.clone(),
                to_search_thread: from_main_thread_tx.clone(),
                search_end: search_end.clone(),
                parameter: params.clone(),
            };
            s.spawn(move || worker.search_thread());
        }
        drop(from_worker_thread_rx);
        drop(from_main_thread_tx);

        let searcher = PowSearcher {
            to_search_thread: from_worker_thread_tx,
            from_search_thread: from_main_thread_rx,
            message_count: get_message_count(&params.plaintext_character_map),
            parameter: params,
            search_end,
        };

        match searcher.run_search() {
            Ok(_) => SearchResult::NotFound,
            Err(SearchError::Found(ret)) => SearchResult::Found(ret),
            Err(_) => SearchResult::UnexpectedError,
        }
    })
}

pub fn search_by_hash_type(
    hash_type: HashType,
    target_hash: &[u8],
    target_hash_mask: &[u8],
    plaintext_character_map: &[Vec<u8>],
    thread_config: &ThreadConfig,
) -> SearchResult {
    macro_rules! hash_type_impl {
        ($hash_type: ty) => {{
            let target_hash = <$hash_type as Hash>::Output::from_slice(target_hash);
            if target_hash.is_none() {
                return SearchResult::InvalidTargetHashLength;
            }
            let target_hash_mask = <$hash_type as Hash>::Output::from_slice(target_hash_mask);
            if target_hash_mask.is_none() {
                return SearchResult::InvalidTargetHashMaskLength;
            }

            let search_param = PowSearchParameters::<$hash_type> {
                plaintext_character_map: plaintext_character_map.to_vec(),
                target_hash: target_hash.unwrap(),
                target_hash_mask: target_hash_mask.unwrap(),
            };
            search(search_param, thread_config)
        }};
    }
    match hash_type {
        HashType::Md5 => hash_type_impl!(Md5),
        HashType::Sha1 => hash_type_impl!(Sha1),
        HashType::Sha224 => hash_type_impl!(Sha224),
        HashType::Sha256 => hash_type_impl!(Sha256),
        HashType::Sha384 => hash_type_impl!(Sha384),
        HashType::Sha512 => hash_type_impl!(Sha512),
    }
}

fn get_message_count(plaintext_character_map: &[Vec<u8>]) -> Vec<usize> {
    let mut message_count = vec![0; plaintext_character_map.len()];
    if !plaintext_character_map.is_empty() {
        message_count[plaintext_character_map.len() - 1] =
            plaintext_character_map[plaintext_character_map.len() - 1].len();
        for i in (0..plaintext_character_map.len() - 1).rev() {
            message_count[i] =
                message_count[i + 1].saturating_mul(plaintext_character_map[i].len());
        }
    }
    message_count
}

#[cfg(all(
    test,
    any(feature = "backend-openssl", feature = "backend-rust-crypto")
))]
mod tests {
    use super::{get_message_count, search, PowSearchParameters};
    use crate::{Hash as _, SearchResult};

    #[test]
    #[cfg(feature = "backend-openssl")]
    fn test_search_openssl_md5() {
        use crate::openssl::Md5;
        let md5_abcde = b"\xab\x56\xb4\xd9\x2b\x40\x71\x3a\xcc\x5a\xf8\x99\x85\xd4\xb7\x86";
        let md5_mask = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        let search_params = PowSearchParameters {
            target_hash: *md5_abcde,
            target_hash_mask: *md5_mask,
            plaintext_character_map: vec![vec![b'a', b'b', b'c', b'd', b'e']; 5],
        };
        match search::<Md5>(search_params, Some(2)) {
            SearchResult::Found(found) => {
                assert_eq!(found, vec![b'a', b'b', b'c', b'd', b'e']);
            }
            SearchResult::NotFound => {
                panic!("Unexpected not found");
            }
            _ => {
                panic!("Unexpected error");
            }
        }

        // 先頭16bitがzeroであるデータの生成のテスト
        let md5_zero = &[0u8; 16];
        let md5_mask = &[255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let search_params = PowSearchParameters {
            target_hash: *md5_zero,
            target_hash_mask: *md5_mask,
            plaintext_character_map: vec![vec![b'a', b'b', b'c', b'd', b'e']; 20],
        };
        match search::<Md5>(search_params, None) {
            SearchResult::Found(found) => {
                let digest = Md5::hash(&found);
                assert_eq!(digest[0], 0);
                assert_eq!(digest[1], 0);
            }
            SearchResult::NotFound => {
                panic!("Unexpected not found");
            }
            _ => {
                panic!("Unexpected error");
            }
        }
    }

    #[test]
    #[cfg(feature = "backend-rust-crypto")]
    fn test_search_rust_crypto_md5() {
        use crate::{rust_crypto::Md5, ThreadConfig};
        let md5_abcde = b"\xab\x56\xb4\xd9\x2b\x40\x71\x3a\xcc\x5a\xf8\x99\x85\xd4\xb7\x86";
        let md5_mask = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        let search_params = PowSearchParameters {
            target_hash: *md5_abcde,
            target_hash_mask: *md5_mask,
            plaintext_character_map: vec![vec![b'a', b'b', b'c', b'd', b'e']; 5],
        };
        match search::<Md5>(
            search_params,
            &ThreadConfig {
                thread_count: Some(2),
                cancel: None,
            },
        ) {
            SearchResult::Found(found) => {
                assert_eq!(found, vec![b'a', b'b', b'c', b'd', b'e']);
            }
            SearchResult::NotFound => {
                panic!("Unexpected not found");
            }
            _ => {
                panic!("Unexpected error");
            }
        }

        // 先頭16bitがzeroであるデータの生成のテスト
        let md5_zero = &[0u8; 16];
        let md5_mask = &[255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let search_params = PowSearchParameters {
            target_hash: *md5_zero,
            target_hash_mask: *md5_mask,
            plaintext_character_map: vec![vec![b'a', b'b', b'c', b'd', b'e']; 20],
        };
        match search::<Md5>(
            search_params,
            &ThreadConfig {
                thread_count: Some(2),
                cancel: None,
            },
        ) {
            SearchResult::Found(found) => {
                let digest = Md5::hash(&found);
                assert_eq!(digest[0], 0);
                assert_eq!(digest[1], 0);
            }
            SearchResult::NotFound => {
                panic!("Unexpected not found");
            }
            _ => {
                panic!("Unexpected error");
            }
        }
    }

    #[test]
    fn test_get_message_count() {
        assert_eq!(
            get_message_count(&vec![
                vec![b'1', b'2', b'3', b'4'],
                vec![b'1', b'2', b'3'],
                vec![b'1', b'2'],
                vec![b'1', b'2', b'3', b'4'],
            ]),
            vec![96, 24, 8, 4]
        );

        let v = vec![(0..=255).collect::<Vec<u8>>(); 10];
        assert_eq!(
            get_message_count(&v),
            vec![
                18446744073709551615,
                18446744073709551615,
                18446744073709551615,
                72057594037927936,
                281474976710656,
                1099511627776,
                4294967296,
                16777216,
                65536,
                256
            ]
        );
    }
}
