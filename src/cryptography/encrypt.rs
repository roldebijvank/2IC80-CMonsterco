use std::{ fs::File, io::{ Read, Write }, path::{Path, PathBuf} };
use age::{ Decryptor, Encryptor, x25519 };
use std::iter;

use anyhow::Result;

pub fn generate_key() -> (x25519::Identity, x25519::Recipient) {
    let sec_key = x25519::Identity::generate();
    let pub_key = sec_key.to_public();

    (sec_key, pub_key)
}

pub fn encrypt_file(input_path: &Path, pub_key: &x25519::Recipient) -> Result<PathBuf> {
    let output_path = PathBuf::from(input_path.with_added_extension("encrypted"));

    let mut plaintext = Vec::new();
    File::open(input_path)?.read_to_end(&mut plaintext)?;

    // output file
    let mut out = File::create(&output_path)?;

    let encryptor = Encryptor::with_recipients(iter::once(pub_key as _))
        .expect("we provided a recipient");

    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(&plaintext)?;
    writer.finish()?;

    std::fs::remove_file(input_path)?;

    return Ok(output_path);
}

pub fn decrypt_file(input_path: &Path, sec_key: &x25519::Identity) -> Result<()> {
    let output_path = input_path.with_extension("");

    let mut ciphertext = Vec::new();
    File::open(input_path)?.read_to_end(&mut ciphertext)?;

    // output file
    let mut out = File::create(output_path)?;

    let decryptor = Decryptor::new(&ciphertext[..])?;

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(iter::once(sec_key as &dyn age::Identity))?;
    let _ = reader.read_to_end(&mut decrypted);

    let _ = out.write(&decrypted);

    std::fs::remove_file(input_path)?;

    return Ok(());
}
