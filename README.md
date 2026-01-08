# 2IC80-CMonsterco/: Ransomware Simulation

A Rust based project demonstrating ransomware concepts and cryptographic techniques.

## Project Structure

```
2IC80-CMonsterco/
├── ransomware/                         # Ransomware components (client)
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── lib.rs
│       ├── bin/
│       │   ├── encrypt.rs             # encrypt flow
│       │   └── decrypt.rs             # decrypt flow
│       ├── cryptography/
│       │   ├── mod.rs
│       │   ├── encrypt.rs             # XChaCha20Poly1305 encryption/decryption
│       │   ├── keys.rs                # Key parsing/handling helpers
│       │   └── test.txt               # Sample file for testing
│       ├── gui/
│       │   ├── mod.rs
│       │   └── payment.rs             # Payment demand UI
│       └── networking/
│           ├── mod.rs
│           └── client.rs              # Client <-> server communications
│
├── server/                            # Key management server
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       └── cryptography/
│           ├── mod.rs
│           └── key_gen.rs             # Symmetric key generation
│
└── target/                          
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
