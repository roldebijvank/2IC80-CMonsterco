use std::fs;
use std::path::Path;
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

pub fn decrypt_file(path: &Path, pk: &PublicKey, sk: &SecretKey) -> Result<(), Box<dyn std::error::Error>> {
    // remove extension (remove .enc)
    let orig_path = path.with_extension("");
    // get encrypted key FILENAME.ORIGINAL_EXTENSION.meta
    let meta_path = format!("{}.meta", orig_path.to_string_lossy());
    let encrypted_key = fs::read(&meta_path)?;

    let sym_key_bytes = decrypt_key(pk, sk, &encrypted_key)?;
    let sym_key = aead::Key::from_slice(&sym_key_bytes)
        .ok_or("symmetric key bytes not valid")? as aead::Key;

    // Read encrypted file
    let data = fs::read(path)?;

    // extract nonce (first 24) and ciphertext (rest)
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = aead::Nonce::from_slice(nonce_bytes)
        .ok_or("nonce_bytes has incorrect format")? as aead::Nonce;

    // Decrypt
    let plaintext = aead::open(&ciphertext, None, &nonce, &sym_key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    // write old file back and delete encrypted file
    fs::write(orig_path, plaintext)?;
    fs::remove_file(path)?;
    fs::remove_file(meta_path)?;

    Ok(())
}

pub fn decrypt_folder(folder_path: &Path, pk: &PublicKey, sk: &SecretKey) -> Result<(), Box<dyn std::error::Error>> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err("folder does not exist or is not a dir".into());
    }

    decrypt_recursively(folder_path, pk, sk)?;
    println!("Decryption completed for folder: {:?}", folder_path);
    Ok(())
}

fn decrypt_recursively(path: &Path, pk: &PublicKey, sk: &SecretKey) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_file() && path.extension().map_or(false, |ext| ext == "enc") {
        decrypt_file(path, pk, sk)?;
        println!("Decrypted file: {:?}", path);
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            decrypt_recursively(&entry.path(), pk, sk)?;
        }
    }
    Ok(())
}