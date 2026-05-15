use wasm_bindgen::prelude::*;

// TODO: implement chacha8 and chacha12 stream ciphers

#[wasm_bindgen]
pub fn chacha8(_key: &[u8], _nonce: &[u8], _data: &[u8]) -> Vec<u8> {
    unimplemented!("chacha8 not yet implemented")
}

#[wasm_bindgen]
pub fn chacha12(_key: &[u8], _nonce: &[u8], _data: &[u8]) -> Vec<u8> {
    unimplemented!("chacha12 not yet implemented")
}
