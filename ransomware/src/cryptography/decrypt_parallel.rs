use anyhow::Result;
use std::fs;
use std::path::Path;

use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use crate::cryptography::keys::decrypt_key;
use crate::debug_log;

pub fn decrypt_file(
    path: &Path,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    // remove extension (remove .enc)
    let orig_path = path.with_extension("");
    // get encrypted key FILENAME.ORIGINAL_EXTENSION.meta
    let meta_path = format!("{}.meta", orig_path.to_string_lossy());
    let encrypted_key = fs::read(&meta_path)?;

    let sym_key_bytes = decrypt_key(pk, sk, &encrypted_key)?;
    let sym_key =
        aead::Key::from_slice(&sym_key_bytes).ok_or("symmetric key bytes not valid")? as aead::Key;

    // Read encrypted file
    let data = fs::read(path)?;

    // extract nonce (first 24) and ciphertext (rest)
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = aead::Nonce::from_slice(nonce_bytes).ok_or("nonce_bytes has incorrect format")?
        as aead::Nonce;

    // Decrypt
    let plaintext = aead::open(&ciphertext, None, &nonce, &sym_key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    // write old file back and delete encrypted file
    fs::write(orig_path, plaintext)?;
    fs::remove_file(path)?;
    fs::remove_file(meta_path)?;

    Ok(())
}

pub fn decrypt_folder(
    folder_path: &Path,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err("folder does not exist or is not a dir".into());
    }

    decrypt_recursively(folder_path, pk, sk)?;
    debug_log!("Decryption completed for folder: {:?}", folder_path);
    Ok(())
}

fn decrypt_recursively(
    path: &Path,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_file() && path.extension().map_or(false, |ext| ext == "enc") {
        decrypt_file(path, pk, sk)?;
        debug_log!("Decrypted file: {:?}", path);
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            decrypt_recursively(&entry.path(), pk, sk)?;
        }
    }
    Ok(())
}

// decrypts a single .enc file (parallel format)
fn decrypt_file_parallel(path: &Path, root: &Path, pk: &PublicKey, sk: &SecretKey) -> Result<()> {
    debug_log!("decrypting: {:?}", path);

    let data = fs::read(path)?;

    // parse header
    let (header, header_size) = crate::cryptography::chunk::FileHeader::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse header: {}", e))?;

    // decrypt symmetric key
    let sym_key_bytes = decrypt_key(pk, sk, &header.encrypted_sym_key)?;
    let sym_key = aead::Key::from_slice(&sym_key_bytes)
        .ok_or_else(|| anyhow::anyhow!("invalid symmetric key"))?;

    // decrypt chunks
    let mut plaintext = Vec::with_capacity(header.original_size as usize);
    let mut offset = header_size;

    for chunk_info in &header.chunks {
        let chunk_data = &data[offset..offset + chunk_info.encrypted_size];
        let nonce = aead::Nonce::from_slice(&chunk_info.nonce)
            .ok_or_else(|| anyhow::anyhow!("invalid nonce"))?;

        let decrypted = aead::open(chunk_data, None, &nonce, &sym_key)
            .map_err(|_| anyhow::anyhow!("decryption failed for chunk {}", chunk_info.sequence))?;

        plaintext.extend_from_slice(&decrypted);
        offset += chunk_info.encrypted_size;
    }

    // verify size
    if plaintext.len() as u64 != header.original_size {
        return Err(anyhow::anyhow!(
            "size mismatch: expected {}, got {}",
            header.original_size,
            plaintext.len()
        ));
    }

    // write original file
    let output_path = root.join(&header.original_filename);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, &plaintext)?;

    // delete encrypted file
    fs::remove_file(path)?;

    debug_log!("restored: {:?}", output_path);
    Ok(())
}

// recursively finds and decrypts .enc files (parallel format)
pub fn decrypt_folder_parallel(folder_path: &Path, pk: &PublicKey, sk: &SecretKey) -> Result<()> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(anyhow::anyhow!("invalid folder path"));
    }

    decrypt_recursive_parallel(folder_path, folder_path, pk, sk)?;
    debug_log!("decryption completed for {:?}", folder_path);
    Ok(())
}

fn decrypt_recursive_parallel(
    root: &Path,
    current: &Path,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<()> {
    if current.is_file() {
        if current.extension().map_or(false, |e| e == "enc") {
            decrypt_file_parallel(current, root, pk, sk)?;
        }
    } else if current.is_dir() {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            decrypt_recursive_parallel(root, &entry.path(), pk, sk)?;
        }
    }
    Ok(())
}
