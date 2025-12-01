use std::{fs, path::{Path}};
use crate::cryptography::encrypt::{generate_key, encrypt_file, decrypt_file};
use age::x25519;
use anyhow::Result;

// default passphrase- most likely should be separately made for each user
const DEFAULT_PASSPHRASE: &str = "default_passphrase";

pub struct FileEncryptor {
    secret_key: x25519::Identity,
    public_key: x25519::Recipient,
    passphrase: String,
}
impl FileEncryptor {
    pub fn new() -> Self {
        let (sec_key, pub_key) = generate_key();
        FileEncryptor {
            secret_key: sec_key,
            public_key: pub_key,
            passphrase: DEFAULT_PASSPHRASE.to_string(),
        }
    }

    pub fn encrypt_folder(&self, folder_path: &Path) -> Result<()> {
        if !folder_path.exists() || !folder_path.is_dir() {
            return Err(anyhow::anyhow!("Invalid folder path"));
        }
        self.encrypt_recursively(folder_path)?;
        println!("Encryption completed for folder: {:?}", folder_path);
        Ok(())
    }

    fn encrypt_recursively(&self, path: &Path) -> Result<()> {
        if path.is_file() {
            encrypt_file(path, &self.public_key)?;
            println!("Encrypted file: {:?}", path);
        } else if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                self.encrypt_recursively(&entry.path())?;
            }
        }
        Ok(())
    }

    pub fn decrypt_folder(&self, folder_path: &Path, input_passphrase: &str) -> Result<()> {
        if input_passphrase != self.passphrase {
            return Err(anyhow::anyhow!("Invalid passphrase"));
        }

        if !folder_path.exists() || !folder_path.is_dir() {
            return Err(anyhow::anyhow!("Invalid folder path"));
        }

        self.decrypt_recursively(folder_path)?;
        println!("Decryption completed for folder: {:?}", folder_path);
        Ok(())
    }

    fn decrypt_recursively(&self, path: &Path) -> Result<()> {
        if path.is_file() && path.extension().map_or(false, |ext| ext == "encrypted") {
            decrypt_file(path, &self.secret_key)?;
            println!("Decrypted file: {:?}", path);
        } else if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                self.decrypt_recursively(&entry.path())?;
            }
        }
        Ok(())
    }
}

