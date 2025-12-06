use rand_core::{TryRngCore, OsRng};

pub fn generate_sym_key() -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];

    OsRng.try_fill_bytes(&mut key)?;

    Ok(key)
}

