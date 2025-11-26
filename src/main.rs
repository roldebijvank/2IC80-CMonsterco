mod cryptography;
use cryptography::encrypt::{ generate_key, encrypt_file, decrypt_file };

use std::{path::Path};

fn main() {
    let (sec_key, pub_key) = generate_key();

    let path = Path::new(""); // CHANGE THIS TO SOME PATH
    let encrypt_path = encrypt_file(path, &pub_key).unwrap();

    let _ = decrypt_file(&encrypt_path, &sec_key);
}
