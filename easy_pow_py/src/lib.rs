use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use ::easy_pow::{search_by_hash_type, HashType, SearchResult, ThreadConfig};
use pyo3::{
    exceptions::{asyncio::CancelledError, PyTypeError},
    prelude::*,
    types::PyBytes,
};

/// Formats the sum of two numbers as string.
#[pyfunction(name = "easy_pow")]
fn easy_pow_py(
    py: Python,
    hash_name: &str,
    plaintext_character_map: Vec<&[u8]>,
    target_hash: &[u8],
    target_hash_mask: &[u8],
) -> PyResult<Option<PyObject>> {
    let hash_type =
        HashType::from_str(hash_name).map_err(|e| PyTypeError::new_err(e.to_string()))?;
    let plaintext_character_map: Vec<Vec<u8>> =
        plaintext_character_map.iter().map(|a| a.to_vec()).collect();
    let cancel = Arc::new(AtomicBool::new(false));
    let thread_config = ThreadConfig {
        thread_count: None,
        cancel: Some(cancel.clone()),
    };
    let target_hash = target_hash.to_vec();
    let target_hash_mask = target_hash_mask.to_vec();

    let thread = std::thread::spawn(move || {
        search_by_hash_type(
            hash_type,
            &target_hash,
            &target_hash_mask,
            &plaintext_character_map,
            &thread_config,
        )
    });

    loop {
        std::thread::sleep(Duration::from_millis(5));
        if let Err(e) = py.check_signals() {
            cancel.store(true, Ordering::Relaxed);
            return Err(e);
        }
        if thread.is_finished() {
            break;
        }
    }

    match thread
        .join()
        .map_err(|_| PyTypeError::new_err("Unexpected Error"))?
    {
        SearchResult::Found(result) => {
            let result = PyBytes::new(py, &result);
            Ok(Some(result.into()))
        }
        SearchResult::NotFound => Ok(None),
        SearchResult::UnexpectedError => Err(PyTypeError::new_err("Unexpected Error")),
        SearchResult::InvalidTargetHashLength => {
            Err(PyTypeError::new_err("target_hash has invalid length"))
        }
        SearchResult::InvalidTargetHashMaskLength => {
            Err(PyTypeError::new_err("target_hash_mask has invalid length"))
        }
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn easy_pow(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(easy_pow_py, m)?)?;
    Ok(())
}
