use anyhow::Result;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::sealedbox;

pub fn generate_sym_key() -> Result<(aead::Key, aead::Nonce)> {
    let key = aead::gen_key();
    let nonce = aead::gen_nonce();

    Ok((key, nonce))
}

pub fn encrypt_key(pk: &PublicKey, sym_key: aead::Key) -> Result<Vec<u8>> {
    let out = sealedbox::seal(sym_key.as_ref(), pk);
    drop(sym_key);
    Ok(out)
}

pub fn decrypt_key(pk: &PublicKey, sk: &SecretKey, enc_key: &Vec<u8>) -> Result<Vec<u8>> {
    Ok(sealedbox::open(enc_key, pk, sk).unwrap())
}
