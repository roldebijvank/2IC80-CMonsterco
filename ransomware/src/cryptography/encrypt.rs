use std::fs;
use std::path::{Path};
use anyhow::Result;

use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use crate::cryptography::keys::{encrypt_key, decrypt_key, generate_sym_key};

pub fn encrypt_file(path: &Path, pk: &PublicKey) -> Result<()> {
    let plaintext = fs::read(path)?;

    let (key, nonce) = generate_sym_key()?;

    let ciphertext = aead::seal(&plaintext, None, &nonce, &key);

    // output is nonce + ciphertext since we need the nonce when decrypting
    let mut out = Vec::with_capacity(nonce.as_ref().len() + ciphertext.len());
    out.extend_from_slice(nonce.as_ref());
    out.extend_from_slice(&ciphertext);

    fs::write(format!("{}.enc", path.to_string_lossy()), out)?;
    fs::remove_file(path)?;

    let encrypted_key = encrypt_key(pk, key)?;

    fs::write(format!("{}.meta", path.to_string_lossy()), &encrypted_key)?;

    Ok(())
}

pub fn encrypt_folder(folder_path: &Path, key: &PublicKey) -> Result<()> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(anyhow::anyhow!("Invalid folder path"));
    }
    encrypt_recursively(folder_path, key)?;
    println!("Encryption completed for folder: {:?}", folder_path);
    Ok(())
}

fn encrypt_recursively(path: &Path, key: &PublicKey) -> Result<()> {
    if path.is_file() {
        encrypt_file(path, &key)?;
        println!("Encrypted file: {:?}", path);
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            encrypt_recursively(&entry.path(), &key)?;
        }
    }
    Ok(())
}