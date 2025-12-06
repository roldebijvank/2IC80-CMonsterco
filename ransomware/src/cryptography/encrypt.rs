use std::fs;
use std::path::Path;
use anyhow::Result;

use chacha20poly1305::{
    Key, KeyInit, XNonce, XChaCha20Poly1305, aead::{Aead}
};

use rand_core::{TryRngCore, OsRng};

pub fn encrypt_file(path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let plaintext = fs::read(path)?;

    // generate random nonce (24 bits)
    let mut nonce_bytes = [0u8; 24];
    OsRng.try_fill_bytes(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    // output is nonce + ciphertext since we need the nonce when decrypting
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);

    fs::write(format!("{}.enc", path.to_string_lossy()), out)?;
    fs::remove_file(path)?;

    Ok(())
}

pub fn decrypt_file(path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));

    // Read encrypted file
    let data = fs::read(path)?;

    // extract nonce (first 24) and ciphertext (rest)
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    // write old file back and delete encrypted file
    let out_path = path.with_extension("");
    fs::write(out_path, plaintext)?;
    fs::remove_file(path)?;

    Ok(())
}

pub fn encrypt_folder(folder_path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(anyhow::anyhow!("Invalid folder path"));
    }
    encrypt_recursively(folder_path, &key_bytes)?;
    println!("Encryption completed for folder: {:?}", folder_path);
    Ok(())
}

fn encrypt_recursively(path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    if path.is_file() {
        encrypt_file(path, &key_bytes)?;
        println!("Encrypted file: {:?}", path);
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            encrypt_recursively(&entry.path(), &key_bytes)?;
        }
    }
    Ok(())
}

pub fn decrypt_folder(folder_path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(anyhow::anyhow!("Invalid folder path"));
    }

    decrypt_recursively(folder_path, &key_bytes)?;
    println!("Decryption completed for folder: {:?}", folder_path);
    Ok(())
}

fn decrypt_recursively(path: &Path, key_bytes: &[u8; 32]) -> Result<()> {
    if path.is_file() && path.extension().map_or(false, |ext| ext == "enc") {
        decrypt_file(path, &key_bytes)?;
        println!("Decrypted file: {:?}", path);
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            decrypt_recursively(&entry.path(), &key_bytes)?;
        }
    }
    Ok(())
}