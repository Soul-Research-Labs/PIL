//! # pil-rpc
//!
//! Axum HTTP server for PIL. Provides REST API endpoints for:
//! - Pool status
//! - Deposit, transfer, withdraw
//! - Epoch root queries
//! - Epoch finalization (admin-only, requires API key)

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
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
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

/// Shared application state backed by real pool + epoch manager.
pub struct AppState {
    pub pool: PrivacyPool,
    pub epoch_manager: EpochManager,
    pub proving_keys: Arc<ProvingKeys>,
    /// Optional API key for admin endpoints (finalize-epoch).
    /// If None, admin endpoints are open (for testing).
    pub admin_api_key: Option<String>,
    /// Allowed CORS origins. If empty, no origins are allowed (restrictive).
    pub allowed_origins: Vec<String>,
}

impl AppState {
    pub fn new(proving_keys: Arc<ProvingKeys>) -> Self {
        Self {
            pool: PrivacyPool::new(),
            epoch_manager: EpochManager::new(3600),
            proving_keys,
            admin_api_key: None,
            allowed_origins: Vec::new(),
        }
    }

    /// Create with an admin API key for protected endpoints.
    pub fn with_api_key(proving_keys: Arc<ProvingKeys>, api_key: String) -> Self {
        Self {
            pool: PrivacyPool::new(),
            epoch_manager: EpochManager::new(3600),
            proving_keys,
            admin_api_key: Some(api_key),
            allowed_origins: Vec::new(),
        }
    }
}

/// Create the Axum router with all PIL endpoints.
pub fn create_router(state: Arc<RwLock<AppState>>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION,
                        axum::http::HeaderName::from_static("x-api-key")]);

    Router::new()
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/deposit", post(deposit_handler))
        .route("/transfer", post(transfer_handler))
        .route("/withdraw", post(withdraw_handler))
        .route("/nullifier-check", get(nullifier_check_handler))
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
    Unauthorized(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
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

async fn status_handler(State(state): State<Arc<RwLock<AppState>>>) -> Json<StatusResponse> {
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

    // Hold write lock for the entire verify+mutate to prevent TOCTOU
    let mut s = state.write().await;
    let public_inputs = build_transfer_public_inputs(&nullifiers, &commitments, s.pool.root());
    let pi_refs: Vec<&[pil_primitives::types::Base]> =
        public_inputs.iter().map(|v| v.as_slice()).collect();
    pil_verifier::verify_transfer(
        &s.proving_keys.params_transfer,
        &s.proving_keys.transfer_vk,
        &proof_bytes,
        &pi_refs,
    )
    .map_err(|e| AppError::BadRequest(format!("proof verification failed: {e}")))?;

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

    // Hold write lock for the entire verify+mutate to prevent TOCTOU
    let mut s = state.write().await;
    let public_inputs =
        build_withdraw_public_inputs(&nullifiers, &change_cms, s.pool.root(), req.exit_value);
    let pi_refs: Vec<&[pil_primitives::types::Base]> =
        public_inputs.iter().map(|v| v.as_slice()).collect();
    pil_verifier::verify_withdraw(
        &s.proving_keys.params_withdraw,
        &s.proving_keys.withdraw_vk,
        &proof_bytes,
        &pi_refs,
    )
    .map_err(|e| AppError::BadRequest(format!("proof verification failed: {e}")))?;

    let receipt = s
        .pool
        .process_withdraw(
            &nullifiers,
            &change_cms,
            req.exit_value,
            req.asset_id,
            &proof_bytes,
        )
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
    headers: HeaderMap,
) -> Result<Json<FinalizeEpochResponse>, AppError> {
    // Check API key if configured
    {
        let s = state.read().await;
        if let Some(ref expected) = s.admin_api_key {
            let provided = headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
                return Err(AppError::Unauthorized("invalid or missing API key".into()));
            }
        }
    }

    let mut s = state.write().await;
    let old_epoch = s.epoch_manager.current_epoch();
    let root = s.pool.root();
    s.epoch_manager.finalize_epoch(root);
    Ok(Json(FinalizeEpochResponse {
        finalized_epoch: old_epoch,
        new_epoch: s.epoch_manager.current_epoch(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_field_from_hex(hex_str: &str) -> Result<pil_primitives::types::Base, AppError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| AppError::BadRequest(format!("invalid hex: {hex_str}")))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "field element must be 32 bytes".into(),
        ));
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
// GET /nullifier-check?nullifier=<hex>
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NullifierCheckQuery {
    nullifier: String,
}

#[derive(Serialize)]
struct NullifierCheckResponse {
    nullifier: String,
    spent: bool,
}

async fn nullifier_check_handler(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(query): Query<NullifierCheckQuery>,
) -> Result<Json<NullifierCheckResponse>, AppError> {
    let nf = parse_nullifier(&query.nullifier)?;
    let s = state.read().await;
    let spent = s.pool.is_nullifier_spent(&nf);
    Ok(Json(NullifierCheckResponse {
        nullifier: query.nullifier,
        spent,
    }))
}

// ---------------------------------------------------------------------------
// Public input builders for proof verification
// ---------------------------------------------------------------------------

/// Build public inputs for transfer proof verification.
/// Format: [merkle_root, nullifier_0, nullifier_1, ..., commitment_0, commitment_1, ...]
fn build_transfer_public_inputs(
    nullifiers: &[Nullifier],
    commitments: &[Commitment],
    merkle_root: pil_primitives::types::Base,
) -> Vec<Vec<pil_primitives::types::Base>> {
    let mut pi = vec![merkle_root];
    for nf in nullifiers {
        pi.push(nf.0);
    }
    for cm in commitments {
        pi.push(cm.0);
    }
    vec![pi]
}

/// Build public inputs for withdraw proof verification.
/// Format: [merkle_root, nullifier_0, ..., commitment_0, ..., exit_value]
fn build_withdraw_public_inputs(
    nullifiers: &[Nullifier],
    change_commitments: &[Commitment],
    merkle_root: pil_primitives::types::Base,
    exit_value: u64,
) -> Vec<Vec<pil_primitives::types::Base>> {
    let mut pi = vec![merkle_root];
    for nf in nullifiers {
        pi.push(nf.0);
    }
    for cm in change_commitments {
        pi.push(cm.0);
    }
    pi.push(pil_primitives::types::Base::from(exit_value));
    vec![pi]
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
    use std::sync::OnceLock;
    use tower::util::ServiceExt;

    /// Shared proving keys — generated once across all tests.
    fn shared_proving_keys() -> Arc<ProvingKeys> {
        static KEYS: OnceLock<Arc<ProvingKeys>> = OnceLock::new();
        KEYS.get_or_init(|| Arc::new(ProvingKeys::setup().expect("keygen")))
            .clone()
    }

    fn test_state() -> Arc<RwLock<AppState>> {
        Arc::new(RwLock::new(AppState::new(shared_proving_keys())))
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status["pool_balance"], 100);
        assert_eq!(status["note_count"], 1);
    }

    #[tokio::test]
    async fn epoch_roots_empty() {
        let state = test_state();
        let app = create_router(state);
        let resp = app
            .oneshot(Request::get("/epoch-roots").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["current_epoch"], 0);
        assert!(val["epochs"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn nullifier_check_unspent() {
        let state = test_state();
        let app = create_router(state);

        let nf = pil_primitives::types::Base::from(99u64);
        let nf_hex = hex::encode(nf.to_repr().as_ref());

        let resp = app
            .oneshot(
                Request::get(format!("/nullifier-check?nullifier={nf_hex}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["spent"], false);
    }

    #[tokio::test]
    async fn nullifier_check_invalid_hex() {
        let state = test_state();
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::get("/nullifier-check?nullifier=not_hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn transfer_rejects_invalid_proof() {
        let state = test_state();

        // First deposit so the pool has balance
        {
            let mut s = state.write().await;
            let cm = Commitment(pil_primitives::types::Base::from(1u64));
            s.pool.deposit(cm, 100, 0).unwrap();
        }

        let app = create_router(state);

        let nf = pil_primitives::types::Base::from(42u64);
        let nf_hex = hex::encode(nf.to_repr().as_ref());
        let cm = pil_primitives::types::Base::from(2u64);
        let cm_hex = hex::encode(cm.to_repr().as_ref());

        let body = serde_json::json!({
            "proof_bytes": hex::encode(vec![0u8; 64]),
            "nullifiers": [nf_hex],
            "output_commitments": [cm_hex]
        });

        let resp = app
            .oneshot(
                Request::post("/transfer")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Should fail proof verification
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn withdraw_rejects_invalid_proof() {
        let state = test_state();

        // Deposit first
        {
            let mut s = state.write().await;
            let cm = Commitment(pil_primitives::types::Base::from(1u64));
            s.pool.deposit(cm, 100, 0).unwrap();
        }

        let app = create_router(state);

        let nf = pil_primitives::types::Base::from(42u64);
        let nf_hex = hex::encode(nf.to_repr().as_ref());
        let change_cm = pil_primitives::types::Base::from(2u64);
        let change_hex = hex::encode(change_cm.to_repr().as_ref());

        let body = serde_json::json!({
            "proof_bytes": hex::encode(vec![0u8; 64]),
            "nullifiers": [nf_hex],
            "change_commitments": [change_hex],
            "exit_value": 50
        });

        let resp = app
            .oneshot(
                Request::post("/withdraw")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Should fail proof verification
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn finalize_epoch_advances() {
        let state = test_state();

        // Deposit to set a non-trivial root
        {
            let mut s = state.write().await;
            let cm = Commitment(pil_primitives::types::Base::from(1u64));
            s.pool.deposit(cm, 100, 0).unwrap();
        }

        let app = create_router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/finalize-epoch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["finalized_epoch"], 0);
        assert_eq!(val["new_epoch"], 1);

        // Verify epoch roots now has one entry
        let app2 = create_router(state);
        let resp2 = app2
            .oneshot(Request::get("/epoch-roots").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let val2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
        assert_eq!(val2["current_epoch"], 1);
        assert_eq!(val2["epochs"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deposit_invalid_hex_returns_400() {
        let state = test_state();
        let app = create_router(state);

        let body = serde_json::json!({
            "commitment": "not_valid_hex",
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
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn test_state_with_api_key(key: &str) -> Arc<RwLock<AppState>> {
        Arc::new(RwLock::new(AppState::with_api_key(
            shared_proving_keys(),
            key.to_string(),
        )))
    }

    #[tokio::test]
    async fn finalize_epoch_rejects_without_api_key() {
        let state = test_state_with_api_key("secret-admin-key");
        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::post("/finalize-epoch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn finalize_epoch_rejects_wrong_api_key() {
        let state = test_state_with_api_key("secret-admin-key");
        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::post("/finalize-epoch")
                    .header("x-api-key", "wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn finalize_epoch_accepts_correct_api_key() {
        let state = test_state_with_api_key("secret-admin-key");
        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::post("/finalize-epoch")
                    .header("x-api-key", "secret-admin-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn finalize_epoch_open_without_key_configured() {
        let state = test_state();
        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::post("/finalize-epoch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn multiple_deposits_increment_note_count() {
        let state = test_state();

        for i in 0u64..3 {
            let app = create_router(state.clone());
            let cm_field = pil_primitives::types::Base::from(100 + i);
            let cm_hex = hex::encode(cm_field.to_repr().as_ref());
            let body = serde_json::json!({ "commitment": cm_hex, "amount": 50 });
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
        }

        let app = create_router(state);
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["note_count"], 3);
        assert_eq!(val["pool_balance"], 150);
    }

    #[tokio::test]
    async fn epoch_roots_after_multiple_finalizations() {
        let state = test_state();

        {
            let mut s = state.write().await;
            let cm = Commitment(pil_primitives::types::Base::from(1u64));
            s.pool.deposit(cm, 100, 0).unwrap();
            let root = s.pool.root();
            s.epoch_manager.finalize_epoch(root);
            s.epoch_manager.finalize_epoch(root);
        }

        let app = create_router(state);
        let resp = app
            .oneshot(Request::get("/epoch-roots").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["current_epoch"], 2);
        assert_eq!(val["epochs"].as_array().unwrap().len(), 2);
    }
}
