use wasm_bindgen::prelude::*;

// TODO: implement keccak hash and random key generation

#[wasm_bindgen]
pub fn keccak256(_data: &[u8]) -> Vec<u8> {
    unimplemented!("keccak256 not yet implemented")
}

#[wasm_bindgen]
pub fn random_key() -> Vec<u8> {
    unimplemented!("random_key not yet implemented")
}
