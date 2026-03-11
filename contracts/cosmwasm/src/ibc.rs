//! IBC entry points for the PIL privacy pool CosmWasm contract.
//!
//! Implements the IBC channel lifecycle and packet handling for
//! cross-chain epoch nullifier root synchronization.
//!
//! ## Protocol
//!
//! Port: `pil-epoch-sync`
//! Channel ordering: ORDERED (epoch roots must arrive in sequence)
//!
//! Packet flow:
//! 1. Chain A finalizes epoch → sends EpochSyncPacket via IBC
//! 2. Chain B receives packet → stores remote epoch root
//! 3. Chain B can now verify nullifiers against Chain A's epoch root

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_json, to_json_binary, DepsMut, Env, IbcBasicResponse,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg,
    IbcChannelOpenResponse, IbcOrder, IbcPacketAckMsg, IbcPacketReceiveMsg,
    IbcPacketTimeoutMsg, IbcReceiveResponse, StdError, StdResult,
};
use serde::{Deserialize, Serialize};

use crate::state::{REMOTE_EPOCH_ROOTS, RemoteEpochRoot};

/// IBC port and version for PIL epoch sync.
pub const PIL_IBC_VERSION: &str = "pil-epoch-sync-1";

/// Packet data sent between PIL contracts on different chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSyncPacketData {
    /// Source chain domain ID.
    pub source_chain_id: u32,
    /// Epoch number.
    pub epoch: u64,
    /// Hex-encoded nullifier Merkle root for this epoch.
    pub nullifier_root: String,
    /// Number of nullifiers in this epoch.
    pub nullifier_count: u64,
    /// Hex-encoded cumulative root over all epochs.
    pub cumulative_root: String,
}

/// Acknowledgement data sent back after receiving an epoch packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSyncAck {
    pub success: bool,
    pub error: Option<String>,
}

// ─── Channel Lifecycle ───────────────────────────────────────────────

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> StdResult<IbcChannelOpenResponse> {
    let channel = match &msg {
        IbcChannelOpenMsg::OpenInit { channel } => channel,
        IbcChannelOpenMsg::OpenTry {
            channel,
            counterparty_version,
        } => {
            if counterparty_version != PIL_IBC_VERSION {
                return Err(StdError::generic_err(format!(
                    "PIL IBC version mismatch: expected {PIL_IBC_VERSION}, got {counterparty_version}"
                )));
            }
            channel
        }
    };

    // Enforce ORDERED channel
    if channel.order != IbcOrder::Ordered {
        return Err(StdError::generic_err(
            "PIL epoch sync requires ORDERED channels",
        ));
    }

    // Verify version on OpenInit
    if channel.version != PIL_IBC_VERSION {
        return Err(StdError::generic_err(format!(
            "PIL IBC version mismatch: expected {PIL_IBC_VERSION}, got {}",
            channel.version,
        )));
    }

    Ok(Some(cosmwasm_std::Ibc3ChannelOpenResponse {
        version: PIL_IBC_VERSION.to_string(),
    }))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_connect(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> StdResult<IbcBasicResponse> {
    let channel_id = match &msg {
        IbcChannelConnectMsg::OpenAck {
            channel,
            counterparty_version,
        } => {
            if counterparty_version != PIL_IBC_VERSION {
                return Err(StdError::generic_err(
                    "PIL IBC version mismatch on ack",
                ));
            }
            &channel.endpoint.channel_id
        }
        IbcChannelConnectMsg::OpenConfirm { channel } => {
            &channel.endpoint.channel_id
        }
    };

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_channel_connect")
        .add_attribute("channel_id", channel_id))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    let channel_id = match &msg {
        IbcChannelCloseMsg::CloseInit { channel } => {
            &channel.endpoint.channel_id
        }
        IbcChannelCloseMsg::CloseConfirm { channel } => {
            &channel.endpoint.channel_id
        }
    };

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_channel_close")
        .add_attribute("channel_id", channel_id))
}

// ─── Packet Handling ─────────────────────────────────────────────────

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> StdResult<IbcReceiveResponse> {
    let packet_data: EpochSyncPacketData = from_json(&msg.packet.data)?;

    // Store the remote epoch root
    REMOTE_EPOCH_ROOTS.save(
        deps.storage,
        (packet_data.source_chain_id, packet_data.epoch),
        &RemoteEpochRoot {
            source_chain_id: packet_data.source_chain_id,
            epoch: packet_data.epoch,
            nullifier_root: packet_data.nullifier_root.clone(),
            received_at: env.block.time.seconds(),
        },
    )?;

    let ack = EpochSyncAck {
        success: true,
        error: None,
    };

    Ok(IbcReceiveResponse::new(to_json_binary(&ack)?)
        .add_attribute("action", "ibc_receive_epoch_root")
        .add_attribute("source_chain", packet_data.source_chain_id.to_string())
        .add_attribute("epoch", packet_data.epoch.to_string())
        .add_attribute("nullifier_root", packet_data.nullifier_root))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_ack(
    _deps: DepsMut,
    _env: Env,
    msg: IbcPacketAckMsg,
) -> StdResult<IbcBasicResponse> {
    let ack: EpochSyncAck = from_json(&msg.acknowledgement.data)?;

    if !ack.success {
        return Err(StdError::generic_err(format!(
            "epoch sync ack failed: {}",
            ack.error.unwrap_or_default()
        )));
    }

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_packet_ack")
        .add_attribute("success", "true"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_timeout(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketTimeoutMsg,
) -> StdResult<IbcBasicResponse> {
    // Epoch root sync failed — the relayer should retry on next epoch
    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_packet_timeout"))
}
