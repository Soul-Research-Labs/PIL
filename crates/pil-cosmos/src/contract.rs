//! Contract execution logic for the Cosmos privacy pool.

use super::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg, StatusResponse},
    state::{PoolConfig, PoolState, RemoteEpochRoot},
};
use ff::PrimeField;
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
    /// Remote epoch roots received via IBC for cross-chain verification.
    pub remote_epoch_roots: Vec<RemoteEpochRoot>,
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
            remote_epoch_roots: Vec::new(),
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

    /// Deposit with an explicit amount (in a real CosmWasm contract, the amount
    /// would come from `info.funds`).
    pub fn deposit_with_amount(
        &mut self,
        commitment_hex: String,
        amount: u64,
    ) -> Result<ExecuteResponse, ContractError> {
        let field = Self::hex_to_field(&commitment_hex)?;
        let commitment = pil_primitives::types::Commitment(field);

        self.pool
            .deposit(commitment, amount, 0)
            .map_err(|e| ContractError::PoolError(e.to_string()))?;

        self.sync_state();

        Ok(ExecuteResponse::Deposit {
            note_count: self.state.note_count,
        })
    }

    fn handle_deposit(&mut self, commitment_hex: String) -> Result<ExecuteResponse, ContractError> {
        // In a real CosmWasm contract, the deposit amount is extracted from
        // info.funds (the tokens sent with the message).
        // Here we accept the commitment and record it with zero value;
        // callers that have the amount should use `deposit_with_amount`.
        self.deposit_with_amount(commitment_hex, 0)
    }

    fn handle_transfer(
        &mut self,
        _proof: String,
        _merkle_root: String,
        nullifiers: Vec<String>,
        output_commitments: Vec<String>,
        _domain_chain_id: u32,
        _domain_app_id: u32,
    ) -> Result<ExecuteResponse, ContractError> {
        let nfs: Vec<pil_primitives::types::Nullifier> = nullifiers
            .iter()
            .map(|h| Self::hex_to_field(h).map(pil_primitives::types::Nullifier))
            .collect::<Result<_, _>>()?;

        let cms: Vec<pil_primitives::types::Commitment> = output_commitments
            .iter()
            .map(|h| Self::hex_to_field(h).map(pil_primitives::types::Commitment))
            .collect::<Result<_, _>>()?;

        // In production the ZK proof would be verified by pil-verifier
        // before calling process_transfer. The proof bytes are forwarded
        // so the pool can store them if needed.
        let proof_bytes = hex::decode(&_proof).map_err(|_| ContractError::InvalidHex)?;

        let receipt = self
            .pool
            .process_transfer(&nfs, &cms, &proof_bytes)
            .map_err(|e| ContractError::PoolError(e.to_string()))?;

        self.sync_state();

        Ok(ExecuteResponse::Transfer {
            nullifiers_spent: receipt.nullifiers_spent,
        })
    }

    fn handle_withdraw(
        &mut self,
        _proof: String,
        _merkle_root: String,
        nullifiers: Vec<String>,
        change_commitments: Vec<String>,
        exit_amount: u128,
        _recipient: String,
    ) -> Result<ExecuteResponse, ContractError> {
        let nfs: Vec<pil_primitives::types::Nullifier> = nullifiers
            .iter()
            .map(|h| Self::hex_to_field(h).map(pil_primitives::types::Nullifier))
            .collect::<Result<_, _>>()?;

        let cms: Vec<pil_primitives::types::Commitment> = change_commitments
            .iter()
            .map(|h| Self::hex_to_field(h).map(pil_primitives::types::Commitment))
            .collect::<Result<_, _>>()?;

        let proof_bytes = hex::decode(&_proof).map_err(|_| ContractError::InvalidHex)?;

        // exit_amount is u128 from the message; the pool uses u64
        let exit_value = u64::try_from(exit_amount)
            .map_err(|_| ContractError::PoolError("exit amount overflow".into()))?;

        let _receipt = self
            .pool
            .process_withdraw(&nfs, &cms, exit_value, 0, &proof_bytes)
            .map_err(|e| ContractError::PoolError(e.to_string()))?;

        self.sync_state();

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
        source_chain_id: u32,
        epoch: u64,
        nullifier_root: String,
    ) -> Result<ExecuteResponse, ContractError> {
        // Store the remote epoch root for cross-chain nullifier verification
        self.remote_epoch_roots.push(super::state::RemoteEpochRoot {
            source_chain_id,
            epoch,
            nullifier_root,
            received_at_height: 0, // In CosmWasm: env.block.height
        });
        Ok(ExecuteResponse::RemoteEpochReceived)
    }

    /// Decode a hex-encoded 32-byte field element.
    fn hex_to_field(hex_str: &str) -> Result<pil_primitives::types::Base, ContractError> {
        let bytes = hex::decode(hex_str).map_err(|_| ContractError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(ContractError::InvalidCommitment);
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes);
        let opt = pil_primitives::types::Base::from_repr(repr);
        if bool::from(opt.is_some()) {
            Ok(opt.unwrap())
        } else {
            Err(ContractError::InvalidCommitment)
        }
    }

    /// Sync cached PoolState from the underlying PrivacyPool.
    fn sync_state(&mut self) {
        self.state.note_count = self.pool.note_count();
        self.state.merkle_root = hex::encode(format!("{:?}", self.pool.root()));
        self.state.pool_balance = self.pool.balance() as u128;
        self.state.nullifier_count = self.pool.nullifier_count() as u64;
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

    fn make_pool() -> CosmosPrivacyPool {
        CosmosPrivacyPool::instantiate(InstantiateMsg {
            chain_domain_id: 10,
            app_id: 1,
            admin: "cosmos1...".to_string(),
            epoch_duration_secs: 3600,
            ibc_epoch_channel: None,
        })
    }

    /// Helper: deposit a commitment with a known field element value and return its hex.
    fn deposit_field_value(pool: &mut CosmosPrivacyPool, raw: u64, amount: u64) -> String {
        let field = pil_primitives::types::Base::from(raw);
        let hex_str = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&field).as_ref());
        pool.deposit_with_amount(hex_str.clone(), amount).unwrap();
        hex_str
    }

    #[test]
    fn deposit_and_transfer() {
        let mut pool = make_pool();

        // Deposit two notes
        let _cm1 = deposit_field_value(&mut pool, 100, 50);
        let _cm2 = deposit_field_value(&mut pool, 200, 30);
        assert_eq!(pool.pool.note_count(), 2);
        assert_eq!(pool.pool.balance(), 80);

        // Build a transfer: spend 2 nullifiers, produce 1 output
        let nf1 = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&pil_primitives::types::Base::from(1000u64)).as_ref());
        let nf2 = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&pil_primitives::types::Base::from(1001u64)).as_ref());
        let out = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&pil_primitives::types::Base::from(300u64)).as_ref());

        let result = pool.execute(ExecuteMsg::Transfer {
            proof: hex::encode([0u8; 32]),
            merkle_root: "00".repeat(32),
            nullifiers: vec![nf1, nf2],
            output_commitments: vec![out],
            domain_chain_id: 10,
            domain_app_id: 1,
        }).unwrap();

        match result {
            ExecuteResponse::Transfer { nullifiers_spent } => {
                assert_eq!(nullifiers_spent, 2);
            }
            _ => panic!("expected Transfer response"),
        }
        assert_eq!(pool.pool.balance(), 80);
        assert_eq!(pool.pool.note_count(), 3);
        assert_eq!(pool.pool.nullifier_count(), 2);
    }

    #[test]
    fn deposit_and_withdraw() {
        let mut pool = make_pool();

        deposit_field_value(&mut pool, 100, 50);
        assert_eq!(pool.pool.balance(), 50);

        let nf = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&pil_primitives::types::Base::from(2000u64)).as_ref());

        let result = pool.execute(ExecuteMsg::Withdraw {
            proof: hex::encode([0u8; 32]),
            merkle_root: "00".repeat(32),
            nullifiers: vec![nf],
            change_commitments: vec![],
            exit_amount: 30,
            recipient: "cosmos1recipient".to_string(),
        }).unwrap();

        match result {
            ExecuteResponse::Withdraw { exit_amount } => {
                assert_eq!(exit_amount, 30);
            }
            _ => panic!("expected Withdraw response"),
        }
        assert_eq!(pool.pool.balance(), 20);
    }

    #[test]
    fn double_spend_prevented() {
        let mut pool = make_pool();
        deposit_field_value(&mut pool, 100, 50);

        let nf = hex::encode(<pil_primitives::types::Base as ff::PrimeField>::to_repr(&pil_primitives::types::Base::from(3000u64)).as_ref());

        pool.execute(ExecuteMsg::Withdraw {
            proof: hex::encode([0u8; 32]),
            merkle_root: "00".repeat(32),
            nullifiers: vec![nf.clone()],
            change_commitments: vec![],
            exit_amount: 10,
            recipient: "cosmos1x".to_string(),
        }).unwrap();

        // Same nullifier again → should fail
        let err = pool.execute(ExecuteMsg::Withdraw {
            proof: hex::encode([0u8; 32]),
            merkle_root: "00".repeat(32),
            nullifiers: vec![nf],
            change_commitments: vec![],
            exit_amount: 10,
            recipient: "cosmos1x".to_string(),
        });
        assert!(err.is_err());
    }

    #[test]
    fn receive_epoch_root() {
        let mut pool = make_pool();
        pool.execute(ExecuteMsg::ReceiveEpochRoot {
            source_chain_id: 1,
            epoch: 5,
            nullifier_root: "ab".repeat(32),
        }).unwrap();
        assert_eq!(pool.remote_epoch_roots.len(), 1);
        assert_eq!(pool.remote_epoch_roots[0].epoch, 5);
    }
}
