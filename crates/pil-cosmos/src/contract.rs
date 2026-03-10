//! Contract execution logic for the Cosmos privacy pool.

use super::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg, StatusResponse},
    state::{PoolConfig, PoolState},
};
use pil_pool::PrivacyPool;
use serde::{Deserialize, Serialize};

/// High-level Cosmos privacy pool handler.
///
/// In a real CosmWasm contract, this logic lives in the `execute` entry point.
/// This crate provides the business logic separate from the CosmWasm runtime
/// so it can be tested independently and reused across Cosmos chains.
pub struct CosmosPrivacyPool {
    pub config: PoolConfig,
    pub state: PoolState,
    pub pool: PrivacyPool,
}

impl CosmosPrivacyPool {
    /// Initialize a new privacy pool.
    pub fn instantiate(msg: InstantiateMsg) -> Self {
        let config = PoolConfig {
            chain_domain_id: msg.chain_domain_id,
            app_id: msg.app_id,
            admin: msg.admin,
            epoch_duration_secs: msg.epoch_duration_secs,
            ibc_epoch_channel: msg.ibc_epoch_channel,
        };

        Self {
            config,
            state: PoolState::default(),
            pool: PrivacyPool::new(),
        }
    }

    /// Handle an execute message.
    pub fn execute(&mut self, msg: ExecuteMsg) -> Result<ExecuteResponse, ContractError> {
        match msg {
            ExecuteMsg::Deposit { commitment } => self.handle_deposit(commitment),
            ExecuteMsg::Transfer {
                proof,
                merkle_root,
                nullifiers,
                output_commitments,
                domain_chain_id,
                domain_app_id,
            } => self.handle_transfer(
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
            } => self.handle_withdraw(
                proof,
                merkle_root,
                nullifiers,
                change_commitments,
                exit_amount,
                recipient,
            ),
            ExecuteMsg::FinalizeEpoch {} => self.handle_finalize_epoch(),
            ExecuteMsg::PublishEpochRootIBC { channel_id, epoch } => {
                self.handle_publish_epoch_ibc(channel_id, epoch)
            }
            ExecuteMsg::ReceiveEpochRoot {
                source_chain_id,
                epoch,
                nullifier_root,
            } => self.handle_receive_epoch_root(source_chain_id, epoch, nullifier_root),
        }
    }

    /// Handle a query message.
    pub fn query(&self, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
        match msg {
            QueryMsg::Status {} => Ok(QueryResponse::Status(StatusResponse {
                merkle_root: hex::encode(format!("{:?}", self.pool.root())),
                note_count: self.pool.note_count(),
                pool_balance: self.pool.balance() as u128,
                current_epoch: self.state.current_epoch,
                nullifier_count: self.pool.nullifier_count() as u64,
                chain_domain_id: self.config.chain_domain_id,
            })),
            _ => Ok(QueryResponse::NotImplemented),
        }
    }

    fn handle_deposit(&mut self, commitment_hex: String) -> Result<ExecuteResponse, ContractError> {
        let commitment_bytes =
            hex::decode(&commitment_hex).map_err(|_| ContractError::InvalidHex)?;
        if commitment_bytes.len() != 32 {
            return Err(ContractError::InvalidCommitment);
        }

        // In a real CosmWasm contract, we'd extract the deposit amount from
        // info.funds (the tokens sent with the message)
        let deposit_amount = 0u64; // Placeholder: extracted from tx funds

        let commitment = pil_primitives::types::Commitment(
            pil_primitives::types::Base::from(0u64), // Placeholder: proper deserialization
        );

        self.pool
            .deposit(commitment, deposit_amount, 0)
            .map_err(|e| ContractError::PoolError(e.to_string()))?;

        self.state.note_count = self.pool.note_count();
        self.state.merkle_root = hex::encode(format!("{:?}", self.pool.root()));

        Ok(ExecuteResponse::Deposit {
            note_count: self.state.note_count,
        })
    }

    fn handle_transfer(
        &mut self,
        _proof: String,
        _merkle_root: String,
        _nullifiers: Vec<String>,
        _output_commitments: Vec<String>,
        _domain_chain_id: u32,
        _domain_app_id: u32,
    ) -> Result<ExecuteResponse, ContractError> {
        // TODO: Deserialize and verify proof, check nullifiers, update state
        Ok(ExecuteResponse::Transfer {
            nullifiers_spent: 0,
        })
    }

    fn handle_withdraw(
        &mut self,
        _proof: String,
        _merkle_root: String,
        _nullifiers: Vec<String>,
        _change_commitments: Vec<String>,
        exit_amount: u128,
        _recipient: String,
    ) -> Result<ExecuteResponse, ContractError> {
        // TODO: Full implementation with proof verification
        Ok(ExecuteResponse::Withdraw {
            exit_amount,
        })
    }

    fn handle_finalize_epoch(&mut self) -> Result<ExecuteResponse, ContractError> {
        self.state.current_epoch += 1;
        Ok(ExecuteResponse::EpochFinalized {
            epoch: self.state.current_epoch - 1,
        })
    }

    fn handle_publish_epoch_ibc(
        &self,
        _channel_id: String,
        _epoch: u64,
    ) -> Result<ExecuteResponse, ContractError> {
        // In CosmWasm: create an IBC packet with the epoch root
        // IbcMsg::SendPacket { channel_id, data, timeout }
        Ok(ExecuteResponse::IBCPacketSent)
    }

    fn handle_receive_epoch_root(
        &mut self,
        _source_chain_id: u32,
        _epoch: u64,
        _nullifier_root: String,
    ) -> Result<ExecuteResponse, ContractError> {
        // Store the remote epoch root for cross-chain nullifier verification
        Ok(ExecuteResponse::RemoteEpochReceived)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecuteResponse {
    Deposit { note_count: u64 },
    Transfer { nullifiers_spent: usize },
    Withdraw { exit_amount: u128 },
    EpochFinalized { epoch: u64 },
    IBCPacketSent,
    RemoteEpochReceived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResponse {
    Status(StatusResponse),
    NotImplemented,
}

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid commitment (must be 32 bytes)")]
    InvalidCommitment,
    #[error("pool error: {0}")]
    PoolError(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid proof")]
    InvalidProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiate_cosmos_pool() {
        let pool = CosmosPrivacyPool::instantiate(InstantiateMsg {
            chain_domain_id: 10,
            app_id: 1,
            admin: "cosmos1...".to_string(),
            epoch_duration_secs: 3600,
            ibc_epoch_channel: Some("channel-0".to_string()),
        });

        assert_eq!(pool.config.chain_domain_id, 10);
        assert_eq!(pool.pool.note_count(), 0);
    }

    #[test]
    fn query_status() {
        let pool = CosmosPrivacyPool::instantiate(InstantiateMsg {
            chain_domain_id: 10,
            app_id: 1,
            admin: "cosmos1...".to_string(),
            epoch_duration_secs: 3600,
            ibc_epoch_channel: None,
        });

        let result = pool.query(QueryMsg::Status {}).unwrap();
        match result {
            QueryResponse::Status(status) => {
                assert_eq!(status.note_count, 0);
                assert_eq!(status.chain_domain_id, 10);
            }
            _ => panic!("expected Status response"),
        }
    }
}
