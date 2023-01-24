use blake2b_simd::Params;

pub fn blake2b_256(bytes: &[u8]) -> Vec<u8> {
    Params::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize()
        .as_bytes()
        .to_owned()
}

pub fn blake2b_224(bytes: &[u8]) -> Vec<u8> {
    Params::new()
        .hash_length(28)
        .to_state()
        .update(bytes)
        .finalize()
        .as_bytes()
        .to_owned()
}
