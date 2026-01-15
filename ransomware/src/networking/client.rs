use serde_json::{Value};

use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

pub async fn gen_key() -> Result<PublicKey, Box<dyn std::error::Error>> {
    // let url = "http://172.16.96.1:3000/gen-key";     // ip for VM
    let url = "http://192.168.241.1:3000/gen-key";
    // let url = "http://localhost:3000/gen-key";          // for local

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
    // let url = "http://172.16.96.1:3000/get-key";        // ip for VM
    let url = "http://192.168.241.1:3000/get-key";
    // let url = "http://localhost:3000/get-key";       // for local

    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(pk)
                    .send()
                    .await?;
    let body = response.text().await?;

    println!("body: {:?}", &body);

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
    let url = "http://172.16.96.1:3000/mark-paid";      // VM
    // let url = "http://localhost:3000/mark-paid";       //local
    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(pk)
                    .send()
                    .await?;

    Ok(response.status().is_success())
}

//check payment status-client side
pub async fn check_payment(pk: &PublicKey) -> Result<bool, Box<dyn std::error::Error>> {
    let url = "http://172.16.96.1:3000/check-payment";  // VM
    // let url = "http://localhost:3000/check-payment";   //local

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