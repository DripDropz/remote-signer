use std::fmt::Error;

use ed25519_dalek::{Keypair, Signer};
use log::debug;
use rand::distributions::{Alphanumeric, DistString};

use crate::blake2b::blake2b_256;

pub struct Challenge {
    pub challenge: String,
    pub challenge_hash: Vec<u8>,
    pub challenge_signature: Vec<u8>,
}

pub fn generate_random_challenge(keypair: &Keypair) -> Result<Challenge, Error> {
    let challenge = format!(
        "remotesigner_{0}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 64)
    );
    debug!("challenge: {challenge}");
    let challenge_hash: Vec<u8> = blake2b_256(challenge.as_bytes());
    debug!("challenge_hash: {0}", hex::encode(&challenge_hash));
    let challenge_signature: Vec<u8> = keypair.sign(&challenge_hash).to_bytes().to_vec();
    debug!(
        "challenge_signature: {0}",
        hex::encode(&challenge_signature)
    );
    Ok(Challenge {
        challenge,
        challenge_hash,
        challenge_signature,
    })
}
