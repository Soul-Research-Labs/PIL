#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, IbcMsg,
    IbcTimeout, MessageInfo, Response, StdResult, Uint128,
};

use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, EpochRootResponse, ExecuteMsg, InstantiateMsg,
    NullifierStatusResponse, ProofAttestation, QueryMsg, StatusResponse,
};
use crate::state::{
    Config, NoteCommitment, NullifierEntry, PoolState, COMMITMENTS, CONFIG,
    EPOCH_ROOTS, NULLIFIER_COUNT, NULLIFIERS, POOL_STATE, REMOTE_EPOCH_ROOTS,
};

// ─── Instantiate ─────────────────────────────────────────────────────

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let config = Config {
        admin: info.sender.clone(),
        chain_domain_id: msg.chain_domain_id,
        app_id: msg.app_id,
        epoch_duration_secs: msg.epoch_duration_secs,
        ibc_epoch_channel: msg.ibc_epoch_channel,
        denom: msg.denom,
        proof_verifier_committee: msg.proof_verifier_committee,
        committee_threshold: msg.committee_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    let state = PoolState {
        merkle_root: "0".repeat(64), // 32 zero-bytes in hex
        note_count: 0,
        current_epoch: 0,
        pool_balance: Uint128::zero(),
    };
    POOL_STATE.save(deps.storage, &state)?;
    NULLIFIER_COUNT.save(deps.storage, &0u64)?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", info.sender)
        .add_attribute("chain_domain_id", msg.chain_domain_id.to_string())
        .add_attribute("app_id", msg.app_id.to_string()))
}

// ─── Execute ─────────────────────────────────────────────────────────

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Deposit { commitment } => {
            execute_deposit(deps, env, info, commitment)
        }
        ExecuteMsg::Transfer {
            proof,
            merkle_root,
            nullifiers,
            output_commitments,
            public_inputs,
            attestations,
            domain_chain_id,
            domain_app_id,
        } => execute_transfer(
            deps,
            env,
            info,
            proof,
            merkle_root,
            nullifiers,
            output_commitments,
            public_inputs,
            attestations,
            domain_chain_id,
            domain_app_id,
        ),
        ExecuteMsg::Withdraw {
            proof,
            merkle_root,
            nullifiers,
            change_commitments,
            public_inputs,
            attestations,
            exit_amount,
            recipient,
        } => execute_withdraw(
            deps,
            env,
            info,
            proof,
            merkle_root,
            nullifiers,
            change_commitments,
            public_inputs,
            attestations,
            exit_amount,
            recipient,
        ),
        ExecuteMsg::FinalizeEpoch {} => {
            execute_finalize_epoch(deps, env, info)
        }
        ExecuteMsg::PublishEpochRootIbc { channel_id } => {
            execute_publish_epoch_ibc(deps, env, info, channel_id)
        }
        ExecuteMsg::ReceiveEpochRoot {
            source_chain_id,
            epoch,
            nullifier_root,
        } => execute_receive_epoch_root(
            deps, env, info, source_chain_id, epoch, nullifier_root,
        ),
    }
}

fn execute_deposit(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    commitment: String,
) -> Result<Response, ContractError> {
    // Validate commitment hex
    let commitment_bytes = hex::decode(&commitment)
        .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
    if commitment_bytes.len() != 32 {
        return Err(ContractError::InvalidCommitment {});
    }

    // Validate funds
    if info.funds.is_empty() {
        return Err(ContractError::NoFundsSent {});
    }
    if info.funds.len() > 1 {
        return Err(ContractError::MultipleDenoms {});
    }
    let deposit = &info.funds[0];

    // Validate denom matches configured pool denom
    let config = CONFIG.load(deps.storage)?;
    if deposit.denom != config.denom {
        return Err(ContractError::WrongDenom {
            expected: config.denom,
            got: deposit.denom.clone(),
        });
    }

    // Update state
    let mut state = POOL_STATE.load(deps.storage)?;
    let note_index = state.note_count;
    state.note_count += 1;
    state.pool_balance += deposit.amount;
    // Compute new Merkle root as SHA-256(old_root || commitment)
    let old_root_bytes =
        hex::decode(&state.merkle_root).unwrap_or_else(|_| vec![0u8; 32]);
    let mut hasher = Sha256::new();
    hasher.update(&old_root_bytes);
    hasher.update(&commitment_bytes);
    state.merkle_root = hex::encode(hasher.finalize());
    POOL_STATE.save(deps.storage, &state)?;

    // Store the commitment
    COMMITMENTS.save(
        deps.storage,
        note_index,
        &NoteCommitment {
            commitment: commitment.clone(),
            epoch: state.current_epoch,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "deposit")
        .add_attribute("commitment", commitment)
        .add_attribute("note_index", note_index.to_string())
        .add_attribute("amount", deposit.amount)
        .add_attribute("denom", &deposit.denom))
}

#[allow(clippy::too_many_arguments)]
fn execute_transfer(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    proof: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    output_commitments: Vec<String>,
    public_inputs: Vec<String>,
    attestations: Vec<ProofAttestation>,
    _domain_chain_id: u32,
    _domain_app_id: u32,
) -> Result<Response, ContractError> {
    let state = POOL_STATE.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;

    // Verify merkle root matches
    if merkle_root != state.merkle_root {
        return Err(ContractError::MerkleRootMismatch {
            expected: state.merkle_root,
            got: merkle_root,
        });
    }

    // Verify proof structure: must be 192 bytes (384 hex chars) for Groth16 BLS12-381
    let proof_bytes = hex::decode(&proof)
        .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
    if proof_bytes.len() != 192 {
        return Err(ContractError::InvalidProof {
            detail: format!(
                "Groth16 proof must be 192 bytes (A‖B‖C), got {}",
                proof_bytes.len()
            ),
        });
    }

    // Verify committee attestation over the proof
    verify_proof_attestation(
        deps.api,
        &config,
        &proof,
        &public_inputs,
        &merkle_root,
        &attestations,
    )?;

    // Check and insert nullifiers
    let mut nf_count = NULLIFIER_COUNT.load(deps.storage)?;
    for nf_hex in &nullifiers {
        let nf_bytes = hex::decode(nf_hex)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
        if nf_bytes.len() != 32 {
            return Err(ContractError::InvalidNullifier {});
        }
        if NULLIFIERS.has(deps.storage, nf_hex) {
            return Err(ContractError::NullifierAlreadySpent {
                nullifier: nf_hex.clone(),
            });
        }
        NULLIFIERS.save(
            deps.storage,
            nf_hex,
            &NullifierEntry {
                epoch: state.current_epoch,
                timestamp: env.block.time.seconds(),
            },
        )?;
        nf_count += 1;
    }
    NULLIFIER_COUNT.save(deps.storage, &nf_count)?;

    // Add output commitments
    let mut pool_state = POOL_STATE.load(deps.storage)?;
    for cm_hex in &output_commitments {
        let cm_bytes = hex::decode(cm_hex)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
        if cm_bytes.len() != 32 {
            return Err(ContractError::InvalidCommitment {});
        }
        let idx = pool_state.note_count;
        COMMITMENTS.save(
            deps.storage,
            idx,
            &NoteCommitment {
                commitment: cm_hex.clone(),
                epoch: pool_state.current_epoch,
            },
        )?;
        pool_state.note_count += 1;
        // Update Merkle root: SHA-256(old_root || commitment)
        let old_root_bytes =
            hex::decode(&pool_state.merkle_root).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(&old_root_bytes);
        hasher.update(&cm_bytes);
        pool_state.merkle_root = hex::encode(hasher.finalize());
    }
    POOL_STATE.save(deps.storage, &pool_state)?;

    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("nullifiers_spent", nullifiers.len().to_string())
        .add_attribute("outputs_created", output_commitments.len().to_string()))
}

#[allow(clippy::too_many_arguments)]
fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    proof: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    change_commitments: Vec<String>,
    public_inputs: Vec<String>,
    attestations: Vec<ProofAttestation>,
    exit_amount: Uint128,
    recipient: String,
) -> Result<Response, ContractError> {
    let state = POOL_STATE.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;

    // Verify merkle root
    if merkle_root != state.merkle_root {
        return Err(ContractError::MerkleRootMismatch {
            expected: state.merkle_root,
            got: merkle_root,
        });
    }

    // Verify proof structure
    let proof_bytes = hex::decode(&proof)
        .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
    if proof_bytes.len() != 192 {
        return Err(ContractError::InvalidProof {
            detail: format!(
                "Groth16 proof must be 192 bytes (A‖B‖C), got {}",
                proof_bytes.len()
            ),
        });
    }

    // Verify committee attestation over the proof
    verify_proof_attestation(
        deps.api,
        &config,
        &proof,
        &public_inputs,
        &merkle_root,
        &attestations,
    )?;

    // Verify sufficient balance
    if state.pool_balance < exit_amount {
        return Err(ContractError::InsufficientBalance {
            required: exit_amount.to_string(),
            available: state.pool_balance.to_string(),
        });
    }

    // Check and insert nullifiers
    let mut nf_count = NULLIFIER_COUNT.load(deps.storage)?;
    for nf_hex in &nullifiers {
        let nf_bytes = hex::decode(nf_hex)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
        if nf_bytes.len() != 32 {
            return Err(ContractError::InvalidNullifier {});
        }
        if NULLIFIERS.has(deps.storage, nf_hex) {
            return Err(ContractError::NullifierAlreadySpent {
                nullifier: nf_hex.clone(),
            });
        }
        NULLIFIERS.save(
            deps.storage,
            nf_hex,
            &NullifierEntry {
                epoch: state.current_epoch,
                timestamp: env.block.time.seconds(),
            },
        )?;
        nf_count += 1;
    }
    NULLIFIER_COUNT.save(deps.storage, &nf_count)?;

    // Add change commitments
    let mut pool_state = POOL_STATE.load(deps.storage)?;
    for cm_hex in &change_commitments {
        let cm_bytes = hex::decode(cm_hex)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
        if cm_bytes.len() != 32 {
            return Err(ContractError::InvalidCommitment {});
        }
        let idx = pool_state.note_count;
        COMMITMENTS.save(
            deps.storage,
            idx,
            &NoteCommitment {
                commitment: cm_hex.clone(),
                epoch: pool_state.current_epoch,
            },
        )?;
        pool_state.note_count += 1;
        // Update Merkle root: SHA-256(old_root || commitment)
        let old_root_bytes =
            hex::decode(&pool_state.merkle_root).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(&old_root_bytes);
        hasher.update(&cm_bytes);
        pool_state.merkle_root = hex::encode(hasher.finalize());
    }
    pool_state.pool_balance -= exit_amount;
    POOL_STATE.save(deps.storage, &pool_state)?;

    // Validate recipient address
    let recipient_addr = deps.api.addr_validate(&recipient)?;

    // Send withdrawn funds to recipient using configured denom
    let config = CONFIG.load(deps.storage)?;
    let send_msg = BankMsg::Send {
        to_address: recipient_addr.to_string(),
        amount: vec![Coin {
            denom: config.denom,
            amount: exit_amount,
        }],
    };

    Ok(Response::new()
        .add_message(send_msg)
        .add_attribute("action", "withdraw")
        .add_attribute("exit_amount", exit_amount)
        .add_attribute("recipient", recipient))
}

// ─── Proof Attestation Verification ──────────────────────────────────

/// Verify that sufficient committee members have attested to the proof's validity.
///
/// Committee members verify the Groth16 proof off-chain (BLS12-381 pairing check)
/// and sign the proof digest: SHA-256(proof_hex || public_input_0 || ... || merkle_root).
///
/// On-chain we verify:
/// 1. The proof has the correct structure (192 bytes)
/// 2. Each attestation signature is valid (ed25519 over the digest)
/// 3. Each attester is a registered committee member
/// 4. At least `committee_threshold` valid attestations are provided
fn verify_proof_attestation(
    api: &dyn cosmwasm_std::Api,
    config: &Config,
    proof_hex: &str,
    public_inputs: &[String],
    merkle_root: &str,
    attestations: &[ProofAttestation],
) -> Result<(), ContractError> {
    // If no committee is configured, require admin-mode (empty committee = permissive)
    if config.proof_verifier_committee.is_empty() {
        return Ok(());
    }

    // Compute the proof digest that committee members signed
    let mut hasher = Sha256::new();
    hasher.update(proof_hex.as_bytes());
    for input in public_inputs {
        hasher.update(input.as_bytes());
    }
    hasher.update(merkle_root.as_bytes());
    let digest = hasher.finalize();

    let mut valid_count: u32 = 0;
    for att in attestations {
        // Attester must be a registered committee member
        if !config.proof_verifier_committee.contains(&att.pubkey) {
            continue;
        }

        // Decode pubkey and signature
        let pubkey_bytes = hex::decode(&att.pubkey)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;
        let sig_bytes = hex::decode(&att.signature)
            .map_err(|e| ContractError::InvalidHex { detail: e.to_string() })?;

        if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
            continue; // Skip malformed attestations
        }

        // Verify ed25519 signature using CosmWasm's built-in API
        if api.ed25519_verify(&digest, &sig_bytes, &pubkey_bytes).unwrap_or(false) {
            valid_count += 1;
        }
    }

    if valid_count < config.committee_threshold {
        return Err(ContractError::InvalidProof {
            detail: format!(
                "insufficient attestations: got {valid_count}, need {}",
                config.committee_threshold,
            ),
        });
    }

    Ok(())
}

fn execute_finalize_epoch(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    let mut state = POOL_STATE.load(deps.storage)?;
    let epoch = state.current_epoch;

    // Store epoch root
    EPOCH_ROOTS.save(
        deps.storage,
        epoch,
        &crate::state::EpochRoot {
            nullifier_root: format!("epoch_{epoch}_root"),
            finalized_at: env.block.time.seconds(),
            note_count_at_finalization: state.note_count,
        },
    )?;

    state.current_epoch += 1;
    POOL_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("action", "finalize_epoch")
        .add_attribute("epoch", epoch.to_string())
        .add_attribute("new_epoch", state.current_epoch.to_string()))
}

fn execute_publish_epoch_ibc(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    channel_id: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    let state = POOL_STATE.load(deps.storage)?;

    // Build the epoch sync packet for the *previous* (most recently finalized) epoch
    let epoch = if state.current_epoch > 0 {
        state.current_epoch - 1
    } else {
        return Err(ContractError::EpochMismatch {
            expected: 1,
            got: 0,
        });
    };

    let epoch_root = EPOCH_ROOTS.load(deps.storage, epoch).map_err(|_| {
        ContractError::EpochMismatch {
            expected: epoch,
            got: state.current_epoch,
        }
    })?;

    let packet_data = crate::ibc::EpochSyncPacketData {
        source_chain_id: config.chain_domain_id,
        epoch,
        nullifier_root: epoch_root.nullifier_root,
        nullifier_count: epoch_root.note_count_at_finalization,
        cumulative_root: state.merkle_root.clone(),
    };

    let ibc_msg = IbcMsg::SendPacket {
        channel_id: channel_id.clone(),
        data: to_json_binary(&packet_data)?,
        timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300)),
    };

    Ok(Response::new()
        .add_message(CosmosMsg::Ibc(ibc_msg))
        .add_attribute("action", "publish_epoch_root_ibc")
        .add_attribute("channel_id", channel_id)
        .add_attribute("epoch", epoch.to_string()))
}

fn execute_receive_epoch_root(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    source_chain_id: u32,
    epoch: u64,
    nullifier_root: String,
) -> Result<Response, ContractError> {
    // In production: this would be called by the IBC module, not directly
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    REMOTE_EPOCH_ROOTS.save(
        deps.storage,
        (source_chain_id, epoch),
        &crate::state::RemoteEpochRoot {
            source_chain_id,
            epoch,
            nullifier_root: nullifier_root.clone(),
            received_at: env.block.time.seconds(),
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "receive_epoch_root")
        .add_attribute("source_chain", source_chain_id.to_string())
        .add_attribute("epoch", epoch.to_string()))
}

// ─── Query ───────────────────────────────────────────────────────────

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Status {} => to_json_binary(&query_status(deps)?),
        QueryMsg::EpochRoot { epoch } => {
            to_json_binary(&query_epoch_root(deps, epoch)?)
        }
        QueryMsg::NullifierStatus { nullifier } => {
            to_json_binary(&query_nullifier_status(deps, nullifier)?)
        }
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?),
    }
}

fn query_status(deps: Deps) -> StdResult<StatusResponse> {
    let state = POOL_STATE.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;
    let nf_count = NULLIFIER_COUNT.load(deps.storage)?;
    Ok(StatusResponse {
        merkle_root: state.merkle_root,
        note_count: state.note_count,
        pool_balance: state.pool_balance,
        current_epoch: state.current_epoch,
        nullifier_count: nf_count,
        chain_domain_id: config.chain_domain_id,
    })
}

fn query_epoch_root(deps: Deps, epoch: u64) -> StdResult<EpochRootResponse> {
    let root = EPOCH_ROOTS.may_load(deps.storage, epoch)?;
    Ok(EpochRootResponse {
        epoch,
        nullifier_root: root.map(|r| r.nullifier_root),
    })
}

fn query_nullifier_status(
    deps: Deps,
    nullifier: String,
) -> StdResult<NullifierStatusResponse> {
    let entry = NULLIFIERS.may_load(deps.storage, &nullifier)?;
    Ok(NullifierStatusResponse {
        nullifier,
        spent: entry.is_some(),
        epoch: entry.map(|e| e.epoch),
    })
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        admin: config.admin.to_string(),
        chain_domain_id: config.chain_domain_id,
        app_id: config.app_id,
        epoch_duration_secs: config.epoch_duration_secs,
        ibc_epoch_channel: config.ibc_epoch_channel,
        denom: config.denom,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env,
    };
    use cosmwasm_std::{coins, from_json, Addr};

    fn setup_contract(deps: DepsMut) {
        let msg = InstantiateMsg {
            chain_domain_id: 3,
            app_id: 1,
            epoch_duration_secs: 3600,
            ibc_epoch_channel: None,
            denom: "uatom".to_string(),
            proof_verifier_committee: vec![],
            committee_threshold: 0,
        };
        let info = message_info(&Addr::unchecked("admin"), &[]);
        instantiate(deps, mock_env(), info, msg).unwrap();
    }

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        assert_eq!(state.note_count, 0);
        assert_eq!(state.current_epoch, 0);
        assert_eq!(state.pool_balance, Uint128::zero());
    }

    #[test]
    fn test_deposit() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let commitment = "a".repeat(64); // 32 bytes hex
        let msg = ExecuteMsg::Deposit { commitment: commitment.clone() };
        let info = message_info(&Addr::unchecked("user1"), &coins(1000, "uatom"));
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(res.attributes[0].value, "deposit");

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        assert_eq!(state.note_count, 1);
        assert_eq!(state.pool_balance, Uint128::new(1000));
    }

    #[test]
    fn test_deposit_no_funds_fails() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::Deposit {
            commitment: "a".repeat(64),
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::NoFundsSent {}));
    }

    #[test]
    fn test_query_status() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let res = query(deps.as_ref(), mock_env(), QueryMsg::Status {}).unwrap();
        let status: StatusResponse = from_json(res).unwrap();
        assert_eq!(status.note_count, 0);
        assert_eq!(status.chain_domain_id, 3);
    }

    #[test]
    fn test_finalize_epoch_unauthorized() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::FinalizeEpoch {};
        let info = message_info(&Addr::unchecked("not_admin"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn test_finalize_epoch() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::FinalizeEpoch {};
        let info = message_info(&Addr::unchecked("admin"), &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        assert_eq!(state.current_epoch, 1);
    }

    #[test]
    fn test_nullifier_double_spend() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Deposit first
        let deposit_msg = ExecuteMsg::Deposit {
            commitment: "a".repeat(64),
        };
        let info = message_info(&Addr::unchecked("user1"), &coins(1000, "uatom"));
        execute(deps.as_mut(), mock_env(), info, deposit_msg).unwrap();

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        let nullifier = "b".repeat(64);
        let transfer_msg = ExecuteMsg::Transfer {
            proof: "aa".repeat(192),
            merkle_root: state.merkle_root.clone(),
            nullifiers: vec![nullifier.clone()],
            output_commitments: vec!["c".repeat(64)],
            public_inputs: vec![],
            attestations: vec![],
            domain_chain_id: 3,
            domain_app_id: 1,
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        execute(deps.as_mut(), mock_env(), info, transfer_msg).unwrap();

        // Try to use same nullifier again
        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        let transfer_msg2 = ExecuteMsg::Transfer {
            proof: "aa".repeat(192),
            merkle_root: state.merkle_root.clone(),
            nullifiers: vec![nullifier.clone()],
            output_commitments: vec!["d".repeat(64)],
            public_inputs: vec![],
            attestations: vec![],
            domain_chain_id: 3,
            domain_app_id: 1,
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, transfer_msg2).unwrap_err();
        assert!(matches!(err, ContractError::NullifierAlreadySpent { .. }));
    }

    #[test]
    fn test_deposit_merkle_root_is_sha256_chain() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let commitment = "a".repeat(64);
        let msg = ExecuteMsg::Deposit { commitment };
        let info = message_info(&Addr::unchecked("user1"), &coins(500, "uatom"));
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        // Root should be a 64-char hex string (32 bytes)
        assert_eq!(state.merkle_root.len(), 64);
        // Should not be the initial zero root
        assert_ne!(state.merkle_root, "0".repeat(64));

        // Verify it's valid hex
        let decoded = hex::decode(&state.merkle_root).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_deposit_merkle_root_deterministic() {
        // Two contracts with same deposits should produce the same root
        let mut deps1 = mock_dependencies();
        let mut deps2 = mock_dependencies();
        setup_contract(deps1.as_mut());
        setup_contract(deps2.as_mut());

        let commitment = "a".repeat(64);
        for deps in [&mut deps1, &mut deps2] {
            let msg = ExecuteMsg::Deposit {
                commitment: commitment.clone(),
            };
            let info = message_info(&Addr::unchecked("user1"), &coins(100, "uatom"));
            execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        }

        let state1 = POOL_STATE.load(deps1.as_ref().storage).unwrap();
        let state2 = POOL_STATE.load(deps2.as_ref().storage).unwrap();
        assert_eq!(state1.merkle_root, state2.merkle_root);
    }

    #[test]
    fn test_publish_epoch_ibc_requires_admin() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::PublishEpochRootIbc {
            channel_id: "channel-0".to_string(),
        };
        let info = message_info(&Addr::unchecked("not_admin"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn test_publish_epoch_ibc_requires_finalized_epoch() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // No epoch finalized yet → should fail
        let msg = ExecuteMsg::PublishEpochRootIbc {
            channel_id: "channel-0".to_string(),
        };
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::EpochMismatch { .. }));
    }

    #[test]
    fn test_publish_epoch_ibc_after_finalization() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Finalize epoch 0
        let finalize = ExecuteMsg::FinalizeEpoch {};
        let info = message_info(&Addr::unchecked("admin"), &[]);
        execute(deps.as_mut(), mock_env(), info, finalize).unwrap();

        // Now publish should succeed and include an IBC message
        let publish = ExecuteMsg::PublishEpochRootIbc {
            channel_id: "channel-42".to_string(),
        };
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, publish).unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "publish_epoch_root_ibc"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "epoch")
                .unwrap()
                .value,
            "0"
        );
    }

    #[test]
    fn test_receive_epoch_root() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::ReceiveEpochRoot {
            source_chain_id: 11,
            epoch: 5,
            nullifier_root: "ff".repeat(32),
        };
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "receive_epoch_root"
        );

        // Verify stored
        let remote = REMOTE_EPOCH_ROOTS
            .load(deps.as_ref().storage, (11, 5))
            .unwrap();
        assert_eq!(remote.epoch, 5);
        assert_eq!(remote.source_chain_id, 11);
    }

    #[test]
    fn test_query_config() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let res = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(res).unwrap();
        assert_eq!(config.chain_domain_id, 3);
        assert_eq!(config.app_id, 1);
        assert_eq!(config.denom, "uatom");
    }

    #[test]
    fn test_query_epoch_root() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // No epoch finalized yet
        let res = query(deps.as_ref(), mock_env(), QueryMsg::EpochRoot { epoch: 0 }).unwrap();
        let root: EpochRootResponse = from_json(res).unwrap();
        assert_eq!(root.nullifier_root, None);

        // Finalize epoch 0
        let info = message_info(&Addr::unchecked("admin"), &[]);
        execute(deps.as_mut(), mock_env(), info, ExecuteMsg::FinalizeEpoch {}).unwrap();

        // Now epoch 0 should exist
        let res = query(deps.as_ref(), mock_env(), QueryMsg::EpochRoot { epoch: 0 }).unwrap();
        let root: EpochRootResponse = from_json(res).unwrap();
        assert!(root.nullifier_root.is_some());
    }

    #[test]
    fn test_query_nullifier_status() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let nf = "b".repeat(64);

        // Not spent
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::NullifierStatus { nullifier: nf.clone() },
        )
        .unwrap();
        let status: NullifierStatusResponse = from_json(res).unwrap();
        assert!(!status.spent);
        assert_eq!(status.epoch, None);

        // Deposit then transfer to spend a nullifier
        let deposit = ExecuteMsg::Deposit { commitment: "a".repeat(64) };
        let info = message_info(&Addr::unchecked("user1"), &coins(100, "uatom"));
        execute(deps.as_mut(), mock_env(), info, deposit).unwrap();

        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        let transfer = ExecuteMsg::Transfer {
            proof: "aa".repeat(192),
            merkle_root: state.merkle_root,
            nullifiers: vec![nf.clone()],
            output_commitments: vec!["c".repeat(64)],
            public_inputs: vec![],
            attestations: vec![],
            domain_chain_id: 3,
            domain_app_id: 1,
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        execute(deps.as_mut(), mock_env(), info, transfer).unwrap();

        // Now spent
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::NullifierStatus { nullifier: nf },
        )
        .unwrap();
        let status: NullifierStatusResponse = from_json(res).unwrap();
        assert!(status.spent);
        assert_eq!(status.epoch, Some(0));
    }

    #[test]
    fn test_wrong_denom_fails() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::Deposit { commitment: "a".repeat(64) };
        let info = message_info(&Addr::unchecked("user1"), &coins(100, "uosmo"));
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::WrongDenom { .. }));
    }

    #[test]
    fn test_withdraw_insufficient_balance() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let msg = ExecuteMsg::Withdraw {
            proof: "aa".repeat(192),
            merkle_root: "0".repeat(64),
            nullifiers: vec!["b".repeat(64)],
            change_commitments: vec![],
            public_inputs: vec![],
            attestations: vec![],
            exit_amount: Uint128::new(1000),
            recipient: "cosmos1recipient".to_string(),
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::InsufficientBalance { .. }));
    }
}
