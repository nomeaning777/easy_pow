use std::str::FromStr;

use magnus::{
    define_module, exception, function, prelude::*, value::qnil, Error, RArray, RString, Value,
};

use ::easy_pow::{search_by_hash_type, HashType, SearchResult, ThreadConfig};

fn easy_pow(
    hash_name: String,
    plaintext_character_map: RArray,
    target_hash: RString,
    target_hash_mask: RString,
) -> Result<Value, Error> {
    let hash_type = HashType::from_str(&hash_name)
        .map_err(|e| Error::new(exception::arg_error(), e.to_string()))?;
    let mut character_map: Vec<Vec<u8>> = vec![Vec::new(); plaintext_character_map.len()];

    for i in 0..plaintext_character_map.len() {
        let map: RString = plaintext_character_map.entry(i as isize).map_err(|_e| {
            Error::new(
                exception::arg_error(),
                "plaintext_character_map requires List of String",
            )
        })?;
        character_map[i] = map.to_bytes().to_vec();
    }

    let thread_config = ThreadConfig {
        thread_count: None,
        cancel: None,
    };
    let target_hash = target_hash.to_bytes().to_vec();
    let target_hash_mask = target_hash_mask.to_bytes().to_vec();

    match search_by_hash_type(
        hash_type,
        &target_hash,
        &target_hash_mask,
        &character_map,
        &thread_config,
    ) {
        SearchResult::Found(result) => Ok(RString::from_slice(&result).as_value()),
        SearchResult::NotFound => Ok(qnil().as_value()),
        SearchResult::UnexpectedError => Err(Error::new(
            exception::standard_error(),
            "Unexpected error occurred",
        )),
        SearchResult::InvalidTargetHashLength => Err(Error::new(
            exception::arg_error(),
            "target_hash has invalid length",
        )),
        SearchResult::InvalidTargetHashMaskLength => Err(Error::new(
            exception::arg_error(),
            "target_hash_mask has invalid length",
        )),
    }
}

#[magnus::init]
fn init() {
    let module = define_module("EasyPow").unwrap();

    module
        .define_module_function("search", function!(easy_pow, 4))
        .unwrap();
}
