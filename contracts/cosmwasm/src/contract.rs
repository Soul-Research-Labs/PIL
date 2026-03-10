#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, Uint128,
};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, EpochRootResponse, ExecuteMsg, InstantiateMsg,
    NullifierStatusResponse, QueryMsg, StatusResponse,
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
            domain_chain_id,
            domain_app_id,
        ),
        ExecuteMsg::Withdraw {
            proof,
            merkle_root,
            nullifiers,
            change_commitments,
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
    env: Env,
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
    // In production: recompute merkle_root = Poseidon(old_root, commitment)
    // For now: store a hash placeholder
    state.merkle_root = format!(
        "{}{}",
        &state.merkle_root[..32],
        &commitment[..32.min(commitment.len())]
    );
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

fn execute_transfer(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    proof: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    output_commitments: Vec<String>,
    _domain_chain_id: u32,
    _domain_app_id: u32,
) -> Result<Response, ContractError> {
    let state = POOL_STATE.load(deps.storage)?;

    // Verify merkle root matches
    if merkle_root != state.merkle_root {
        return Err(ContractError::MerkleRootMismatch {
            expected: state.merkle_root,
            got: merkle_root,
        });
    }

    // Verify proof is non-empty
    if proof.is_empty() {
        return Err(ContractError::InvalidProof {
            detail: "empty proof".to_string(),
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
    }
    // Update merkle root placeholder
    pool_state.merkle_root = format!("transfer_{}", pool_state.note_count);
    POOL_STATE.save(deps.storage, &pool_state)?;

    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("nullifiers_spent", nullifiers.len().to_string())
        .add_attribute("outputs_created", output_commitments.len().to_string()))
}

fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    proof: String,
    merkle_root: String,
    nullifiers: Vec<String>,
    change_commitments: Vec<String>,
    exit_amount: Uint128,
    recipient: String,
) -> Result<Response, ContractError> {
    let state = POOL_STATE.load(deps.storage)?;

    // Verify merkle root
    if merkle_root != state.merkle_root {
        return Err(ContractError::MerkleRootMismatch {
            expected: state.merkle_root,
            got: merkle_root,
        });
    }

    // Verify proof
    if proof.is_empty() {
        return Err(ContractError::InvalidProof {
            detail: "empty proof".to_string(),
        });
    }

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
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _channel_id: String,
) -> Result<Response, ContractError> {
    // In production: create IBC SendPacket with epoch root data
    // let packet = IbcMsg::SendPacket {
    //     channel_id,
    //     data: to_json_binary(&EpochSyncPacket { ... })?,
    //     timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300)),
    // };
    Ok(Response::new()
        .add_attribute("action", "publish_epoch_root_ibc"))
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
            proof: "deadbeef".to_string(),
            merkle_root: state.merkle_root.clone(),
            nullifiers: vec![nullifier.clone()],
            output_commitments: vec!["c".repeat(64)],
            domain_chain_id: 3,
            domain_app_id: 1,
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        execute(deps.as_mut(), mock_env(), info, transfer_msg).unwrap();

        // Try to use same nullifier again
        let state = POOL_STATE.load(deps.as_ref().storage).unwrap();
        let transfer_msg2 = ExecuteMsg::Transfer {
            proof: "deadbeef".to_string(),
            merkle_root: state.merkle_root.clone(),
            nullifiers: vec![nullifier.clone()],
            output_commitments: vec!["d".repeat(64)],
            domain_chain_id: 3,
            domain_app_id: 1,
        };
        let info = message_info(&Addr::unchecked("user1"), &[]);
        let err = execute(deps.as_mut(), mock_env(), info, transfer_msg2).unwrap_err();
        assert!(matches!(err, ContractError::NullifierAlreadySpent { .. }));
    }
}
