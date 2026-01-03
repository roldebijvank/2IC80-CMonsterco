# 2IC80-CMonsterco/: Ransomware Simulation

A Rust based project demonstrating ransomware concepts and cryptographic techniques.

## Project Structure

```
2IC80-CMonsterco/
├── ransomware/          # Ransomware components
│   ├── src/
│   │   ├── main.rs     
│   │   ├── cryptography/
│   │   │   ├── mod.rs
│   │   │   └── encrypt.rs    # XChaCha20Poly1305 encryption/decryption
│   │   └── gui/
│   │       ├── mod.rs
│   │       └── payment.rs    # Windows payment demand window UI
│   └── Cargo.toml
│
└── server/              # Key management server
    ├── src/
    │   ├── main.rs    
    │   └── cryptography/
    │       ├── mod.rs
    │       └── key_gen.rs    # Symmetric key generation
    └── Cargo.toml
```

## Components

### Ransomware Module
- **Encryption**: XChaCha20Poly1305 (authenticated encryption)
- **Cryptography**: Encryption/decryption functions using 256-bit symmetric keys
- **GUI**: Windows payment demand window with formatted text display

### Server Module
- **Framework**: Built with Axum async web framework
- **Key Management**: Generates and stores symmetric keys
- **Database**: In-memory HashMap for victim IDs and their keys

## Technical Details

### Encryption Algorithm
- **Algorithm**: XChaCha20Poly1305 (256-bit key, 24-byte nonce)
- **Nonce**: Random 24-byte nonce prepended to ciphertext
- **Format**: Encrypted files stored as [nonce + ciphertext]

### Key Generation
- Random 32-byte (256-bit) symmetric keys generated
- Keys stored on server with victim identifier
