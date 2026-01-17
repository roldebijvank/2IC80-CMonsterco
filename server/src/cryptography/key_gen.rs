// use rand_core::{TryRngCore, OsRng};
use sodiumoxide::crypto::box_;

pub fn generate_keys() -> anyhow::Result<(box_::PublicKey, box_::SecretKey)> {
    sodiumoxide::init().expect("libsodium init failed");
    Ok(box_::gen_keypair())
}

