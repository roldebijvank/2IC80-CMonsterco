use serde_json::Value;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use crate::debug_log;

// single ip address used across the system
// const SERVER_IP: &str = "172.16.96.1:3000";     // ip for VM
const SERVER_IP: &str = "host.containers.internal:3000";
// const SERVER_IP: &str = "localhost:3000";       // for local

pub async fn gen_key() -> Result<PublicKey, Box<dyn std::error::Error>> {
    let url = format!("http://{}/gen-key", SERVER_IP);

    loop {
        match gen_key_internal(&url).await {
            Ok(pk) => return Ok(pk),
            Err(_) => {
                debug_log!("failed to connect to server.");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}

async fn gen_key_internal(url: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url)
                    .send()
                    .await?;
    let body = response.text().await?;

    let json: Value = serde_json::from_str(&body)?;
    let arr = json["pk"]
        .as_array()
        .ok_or("public key was not an array")?;

    if arr.len() != 32 {
        return Err("public key array not length 32".into());
    }

    let mut buffer = [0u8; 32];
    for (i, v) in arr.iter().enumerate() {
        buffer[i] = v.as_u64().ok_or("non-integer key value")? as u8;
    }

    let pk = PublicKey::from_slice(&buffer)
        .ok_or("buffer format incorrect")? as PublicKey;

    Ok(pk)
}

pub async fn get_key(pk: &PublicKey) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let url = format!("http://{}/get-key", SERVER_IP);

    loop {
        match get_key_internal(&url, pk).await {
            Ok(sk) => return Ok(sk),
            Err(_) => {
                debug_log!("failed to connect to server.");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}

async fn get_key_internal(
    url: &str,
    pk: &PublicKey,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(pk)
                    .send()
                    .await?;
    let body = response.text().await?;

    debug_log!("body: {:?}", &body);

    let json: Value = serde_json::from_str(&body)?;
    let arr = json["sk"]
        .as_array()
        .ok_or("secret key was not an array")?;

    if arr.len() != 32 {
        return Err("secret key array not length 32".into());
    }

    let mut buffer = [0u8; 32];
    for (i, v) in arr.iter().enumerate() {
        buffer[i] = v.as_u64().ok_or("non-integer key value")? as u8;
    }

    let sk = SecretKey::from_slice(&buffer)
        .ok_or("buffer format incorrect")? as SecretKey;

    Ok(sk)
}
