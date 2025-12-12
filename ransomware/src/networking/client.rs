use serde::Deserialize;
use serde_json::{Value};

pub async fn gen_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let url = "http://172.16.96.1:3000/gen-key";

    let id = "123";

    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(&id)
                    .send()
                    .await?;
    let body = response.text().await?;

    let json: Value = serde_json::from_str(&body)?;
    let arr = json["key"]
        .as_array()
        .ok_or("key was not an array")?;

    if arr.len() != 32 {
        return Err("key array not length 32".into());
    }

    let mut out = [0u8; 32];
    for (i, v) in arr.iter().enumerate() {
        out[i] = v.as_u64().ok_or("non-integer key value")? as u8;
    }

    Ok(out)
}

pub async fn get_key(id: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let url = "http://172.16.96.1:3000/get-key";

    let client = reqwest::Client::new();
    let response = client.post(url)
                    .json(id)
                    .send()
                    .await?;
    let body = response.text().await?;

    let json: Value = serde_json::from_str(&body)?;
    let arr = json["key"]
        .as_array()
        .ok_or("key was not an array")?;

    if arr.len() != 32 {
        return Err("key array not length 32".into());
    }

    let mut out = [0u8; 32];
    for (i, v) in arr.iter().enumerate() {
        out[i] = v.as_u64().ok_or("non-integer key value")? as u8;
    }

    Ok(out)
}