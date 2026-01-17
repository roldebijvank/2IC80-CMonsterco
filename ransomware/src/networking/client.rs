use serde_json::Value;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use crate::debug_log;

// Change this URL to match your server location
const SERVER_URL: &str = "http://localhost:3000";              //  local
// const SERVER_URL: &str = "http://host.containers.local:3000";  //  VM IP 1
// const SERVER_URL: &str = "http://192.168.241.1:3000";             //  VM IP 2 
// const SERVER_URL: &str = "http://172.16.96.1:3000";            //  VM IP 3

pub async fn gen_key() -> Result<PublicKey, Box<dyn std::error::Error>> {
    let url = format!("{}/gen-key", SERVER_URL);

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
    let url = format!("{}/get-key", SERVER_URL);

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
) -> Result<SecretKey, Box<dyn std::error::Error + Send + Sync>> {
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

pub async fn mark_paid(pk: &PublicKey) -> Result<bool, Box<dyn std::error::Error>> {
    let url = format!("{}/mark-paid", SERVER_URL);
    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(pk)
                    .send()
                    .await?;

    Ok(response.status().is_success())
}

//check payment status-client side
pub async fn check_payment(pk: &PublicKey) -> Result<bool, Box<dyn std::error::Error>> {
    let url = format!("{}/check-payment", SERVER_URL);
    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(pk)
                    .send()
                    .await?;
    let body = response.text().await?;

    let json: Value = serde_json::from_str(&body)?;
    let has_paid = json["has_paid"].as_bool().unwrap_or(false);
    Ok(has_paid)
}
