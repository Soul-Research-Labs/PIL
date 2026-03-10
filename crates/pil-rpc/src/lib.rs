//! # pil-rpc
//!
//! Axum HTTP server for PIL. Provides REST API endpoints for:
//! - Pool status
//! - Deposit, transfer, withdraw
//! - Epoch root queries
//! - Epoch finalization

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use ff::PrimeField;
use pil_pool::{EpochManager, PrivacyPool};
use pil_primitives::types::{Commitment, Nullifier};
use pil_prover::ProvingKeys;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

/// Shared application state backed by real pool + epoch manager.
pub struct AppState {
    pub pool: PrivacyPool,
    pub epoch_manager: EpochManager,
    pub proving_keys: Arc<ProvingKeys>,
}

impl AppState {
    pub fn new(proving_keys: Arc<ProvingKeys>) -> Self {
        Self {
            pool: PrivacyPool::new(),
            epoch_manager: EpochManager::new(3600),
            proving_keys,
        }
    }
}

/// Create the Axum router with all PIL endpoints.
pub fn create_router(state: Arc<RwLock<AppState>>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/deposit", post(deposit_handler))
        .route("/transfer", post(transfer_handler))
        .route("/withdraw", post(withdraw_handler))
        .route("/epoch-roots", get(epoch_roots_handler))
        .route("/finalize-epoch", post(finalize_epoch_handler))
        .layer(cors)
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Response / error types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    pool_balance: u64,
    note_count: u64,
    nullifier_count: usize,
    merkle_root: String,
    current_epoch: u64,
    version: String,
    chains: Vec<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

enum AppError {
    BadRequest(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// ---------------------------------------------------------------------------
// GET /status
// ---------------------------------------------------------------------------

async fn status_handler(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<StatusResponse> {
    let s = state.read().await;
    let root_bytes = s.pool.root().to_repr();
    Json(StatusResponse {
        pool_balance: s.pool.balance(),
        note_count: s.pool.note_count(),
        nullifier_count: s.pool.nullifier_count(),
        merkle_root: hex::encode(root_bytes.as_ref()),
        current_epoch: s.epoch_manager.current_epoch(),
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

// ---------------------------------------------------------------------------
// POST /deposit
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DepositRequest {
    /// Hex-encoded commitment (32-byte field element).
    commitment: String,
    amount: u64,
    #[serde(default)]
    asset_id: u64,
}

#[derive(Serialize)]
struct DepositResponse {
    leaf_index: u64,
    merkle_root: String,
    pool_balance: u64,
}

async fn deposit_handler(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, AppError> {
    let cm = parse_commitment(&req.commitment)?;

    let mut s = state.write().await;
    let receipt = s
        .pool
        .deposit(cm, req.amount, req.asset_id)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let root_hex = hex::encode(receipt.root.to_repr().as_ref());
    Ok(Json(DepositResponse {
        leaf_index: receipt.leaf_index,
        merkle_root: root_hex,
        pool_balance: receipt.pool_balance,
    }))
}

// ---------------------------------------------------------------------------
// POST /transfer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TransferRequest {
    /// Hex-encoded proof bytes (verified externally before pool mutation).
    proof_bytes: String,
    /// Hex-encoded nullifiers.
    nullifiers: Vec<String>,
    /// Hex-encoded output commitments.
    output_commitments: Vec<String>,
}

#[derive(Serialize)]
struct TransferResponse {
    nullifiers_spent: usize,
    leaf_indices: Vec<u64>,
    merkle_root: String,
}

async fn transfer_handler(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, AppError> {
    let nullifiers = req
        .nullifiers
        .iter()
        .map(|h| parse_nullifier(h))
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = req
        .output_commitments
        .iter()
        .map(|h| parse_commitment(h))
        .collect::<Result<Vec<_>, _>>()?;
    let proof_bytes = hex::decode(&req.proof_bytes)
        .map_err(|_| AppError::BadRequest("invalid hex in proof_bytes".into()))?;

    let mut s = state.write().await;
    let receipt = s
        .pool
        .process_transfer(&nullifiers, &commitments, &proof_bytes)
        .map_err(|e| match e.to_string().as_str() {
            s if s.contains("already spent") => AppError::Conflict(e.to_string()),
            _ => AppError::Internal(e.to_string()),
        })?;

    let root_hex = hex::encode(receipt.root.to_repr().as_ref());
    Ok(Json(TransferResponse {
        nullifiers_spent: receipt.nullifiers_spent,
        leaf_indices: receipt.leaf_indices,
        merkle_root: root_hex,
    }))
}

// ---------------------------------------------------------------------------
// POST /withdraw
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WithdrawRequest {
    proof_bytes: String,
    nullifiers: Vec<String>,
    change_commitments: Vec<String>,
    exit_value: u64,
    #[serde(default)]
    asset_id: u64,
}

#[derive(Serialize)]
struct WithdrawResponse {
    exit_value: u64,
    leaf_indices: Vec<u64>,
    merkle_root: String,
}

async fn withdraw_handler(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, AppError> {
    let nullifiers = req
        .nullifiers
        .iter()
        .map(|h| parse_nullifier(h))
        .collect::<Result<Vec<_>, _>>()?;
    let change_cms = req
        .change_commitments
        .iter()
        .map(|h| parse_commitment(h))
        .collect::<Result<Vec<_>, _>>()?;
    let proof_bytes = hex::decode(&req.proof_bytes)
        .map_err(|_| AppError::BadRequest("invalid hex in proof_bytes".into()))?;

    let mut s = state.write().await;
    let receipt = s
        .pool
        .process_withdraw(&nullifiers, &change_cms, req.exit_value, req.asset_id, &proof_bytes)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already spent") {
                AppError::Conflict(msg)
            } else if msg.contains("insufficient") {
                AppError::BadRequest(msg)
            } else {
                AppError::Internal(msg)
            }
        })?;

    let root_hex = hex::encode(receipt.root.to_repr().as_ref());
    Ok(Json(WithdrawResponse {
        exit_value: receipt.exit_value,
        leaf_indices: receipt.leaf_indices,
        merkle_root: root_hex,
    }))
}

// ---------------------------------------------------------------------------
// GET /epoch-roots
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EpochRootsResponse {
    current_epoch: u64,
    epochs: Vec<EpochEntry>,
    summary_root: String,
}

#[derive(Serialize)]
struct EpochEntry {
    epoch: u64,
    nullifier_root: String,
}

async fn epoch_roots_handler(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<EpochRootsResponse> {
    let s = state.read().await;
    let epochs: Vec<EpochEntry> = s
        .epoch_manager
        .all_epoch_roots()
        .iter()
        .map(|(epoch, root)| EpochEntry {
            epoch: *epoch,
            nullifier_root: hex::encode(root.to_repr().as_ref()),
        })
        .collect();
    let summary = s.epoch_manager.summary_root();
    Json(EpochRootsResponse {
        current_epoch: s.epoch_manager.current_epoch(),
        epochs,
        summary_root: hex::encode(summary.to_repr().as_ref()),
    })
}

// ---------------------------------------------------------------------------
// POST /finalize-epoch
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FinalizeEpochResponse {
    finalized_epoch: u64,
    new_epoch: u64,
}

async fn finalize_epoch_handler(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<FinalizeEpochResponse> {
    let mut s = state.write().await;
    let old_epoch = s.epoch_manager.current_epoch();
    let root = s.pool.root();
    s.epoch_manager.finalize_epoch(root);
    Json(FinalizeEpochResponse {
        finalized_epoch: old_epoch,
        new_epoch: s.epoch_manager.current_epoch(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_field_from_hex(hex_str: &str) -> Result<pil_primitives::types::Base, AppError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| AppError::BadRequest(format!("invalid hex: {hex_str}")))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest("field element must be 32 bytes".into()));
    }
    let mut repr = <pil_primitives::types::Base as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::from(pil_primitives::types::Base::from_repr(repr))
        .ok_or_else(|| AppError::BadRequest("invalid field element".into()))
}

fn parse_commitment(hex_str: &str) -> Result<Commitment, AppError> {
    parse_field_from_hex(hex_str).map(Commitment)
}

fn parse_nullifier(hex_str: &str) -> Result<Nullifier, AppError> {
    parse_field_from_hex(hex_str).map(Nullifier)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ff::PrimeField;
    use tower::util::ServiceExt;

    fn test_state() -> Arc<RwLock<AppState>> {
        let keys = Arc::new(ProvingKeys::setup().expect("keygen"));
        Arc::new(RwLock::new(AppState::new(keys)))
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let state = test_state();
        let app = create_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["status"], "ok");
    }

    #[tokio::test]
    async fn status_returns_ok() {
        let state = test_state();
        let app = create_router(state);
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deposit_and_status() {
        let state = test_state();
        let app = create_router(state.clone());

        // Create a real commitment
        let cm_field = pil_primitives::types::Base::from(42u64);
        let cm_hex = hex::encode(cm_field.to_repr().as_ref());

        let body = serde_json::json!({
            "commitment": cm_hex,
            "amount": 100
        });

        let resp = app
            .oneshot(
                Request::post("/deposit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check status reflects deposit
        let app2 = create_router(state);
        let resp2 = app2
            .oneshot(
                Request::get("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status["pool_balance"], 100);
        assert_eq!(status["note_count"], 1);
    }

    #[tokio::test]
    async fn epoch_roots_empty() {
        let state = test_state();
        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::get("/epoch-roots")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["current_epoch"], 0);
        assert!(val["epochs"].as_array().unwrap().is_empty());
    }
}
