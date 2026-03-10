//! # pil-rpc
//!
//! Axum HTTP server for PIL. Provides REST API endpoints for:
//! - Pool status
//! - Deposit, transfer, withdraw
//! - Stealth address scanning
//! - Epoch root queries
//! - Cross-chain epoch root relay

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state.
pub struct AppState {
    pub pool_balance: u64,
    pub note_count: u64,
    pub merkle_root: String,
    pub current_epoch: u64,
}

/// Create the Axum router with all PIL endpoints.
pub fn create_router(state: Arc<RwLock<AppState>>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/deposit", post(deposit_handler))
        .route("/transfer", post(transfer_handler))
        .route("/withdraw", post(withdraw_handler))
        .route("/epoch-roots", get(epoch_roots_handler))
        .with_state(state)
}

#[derive(Serialize)]
struct StatusResponse {
    pool_balance: u64,
    note_count: u64,
    merkle_root: String,
    current_epoch: u64,
    version: String,
    chains: Vec<String>,
}

async fn status_handler(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<StatusResponse> {
    let s = state.read().await;
    Json(StatusResponse {
        pool_balance: s.pool_balance,
        note_count: s.note_count,
        merkle_root: s.merkle_root.clone(),
        current_epoch: s.current_epoch,
        version: env!("CARGO_PKG_VERSION").to_string(),
        chains: vec![
            "cardano-mainnet".into(),
            "cardano-preprod".into(),
            "cosmos-hub".into(),
            "osmosis".into(),
            "neutron".into(),
        ],
    })
}

#[derive(Deserialize)]
struct DepositRequest {
    commitment: String,
    amount: u64,
}

async fn deposit_handler(
    State(_state): State<Arc<RwLock<AppState>>>,
    Json(_req): Json<DepositRequest>,
) -> StatusCode {
    // TODO: Process deposit
    StatusCode::ACCEPTED
}

#[derive(Deserialize)]
struct TransferRequest {
    proof_bytes: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    output_commitments: Vec<String>,
    domain_chain_id: u32,
    domain_app_id: u32,
}

async fn transfer_handler(
    State(_state): State<Arc<RwLock<AppState>>>,
    Json(_req): Json<TransferRequest>,
) -> StatusCode {
    StatusCode::ACCEPTED
}

#[derive(Deserialize)]
struct WithdrawRequest {
    proof_bytes: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    change_commitments: Vec<String>,
    exit_value: u64,
    destination: String,
}

async fn withdraw_handler(
    State(_state): State<Arc<RwLock<AppState>>>,
    Json(_req): Json<WithdrawRequest>,
) -> StatusCode {
    StatusCode::ACCEPTED
}

#[derive(Serialize)]
struct EpochRootsResponse {
    epochs: Vec<EpochEntry>,
}

#[derive(Serialize)]
struct EpochEntry {
    epoch: u64,
    nullifier_root: String,
}

async fn epoch_roots_handler(
    State(_state): State<Arc<RwLock<AppState>>>,
) -> Json<EpochRootsResponse> {
    Json(EpochRootsResponse { epochs: vec![] })
}
