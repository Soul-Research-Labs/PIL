//! Transaction batcher for eUTXO concurrency.
//!
//! Cardano's eUTXO model requires that only one transaction can spend a given
//! UTXO at a time. Since the PIL privacy pool uses a single continuing-state
//! UTXO, this creates a concurrency bottleneck: only one operation per block.
//!
//! The batcher solves this by collecting multiple pending operations
//! (deposits, transfers, withdrawals) and consolidating them into a single
//! transaction that atomically applies all operations to the pool state.
//!
//! ## Architecture
//!
//! ```text
//! User A: Deposit 5 ADA ─┐
//! User B: Transfer 2→2   ├─→ [Batcher] ─→ Single Cardano TX
//! User C: Withdraw 1 ADA ┘       │          (1 pool input, 1 pool output,
//!                                 │           N nullifier outputs)
//!                                 ▼
//!                         Merged proof or
//!                         per-op proof list
//! ```

use super::datum::{NullifierDatum, PoolDatum};
use super::redeemer::{DepositRedeemer, TransferRedeemer, WithdrawRedeemer};
use super::transaction::CardanoTxBuilder;
use super::utxo::UtxoRef;
use std::collections::VecDeque;

/// Maximum number of operations per batch.
/// Constrained by Cardano's 16KB transaction size limit and execution unit budget.
const MAX_BATCH_SIZE: usize = 8;

/// Maximum total proof bytes per batch (Cardano metadata limit).
const MAX_BATCH_PROOF_BYTES: usize = 12_288; // 12KB leaves room for tx overhead

/// A pending operation waiting to be batched.
#[derive(Debug, Clone)]
pub enum PendingOp {
    Deposit {
        commitment: [u8; 32],
        amount: u64,
        asset_id: u64,
    },
    Transfer {
        proof: Vec<u8>,
        merkle_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
        domain_chain_id: u32,
        domain_app_id: u32,
    },
    Withdraw {
        proof: Vec<u8>,
        merkle_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        change_commitments: Vec<[u8; 32]>,
        exit_value: u64,
        destination_address: Vec<u8>,
    },
}

impl PendingOp {
    /// Estimated size contribution of this operation to the batch transaction.
    pub fn estimated_size(&self) -> usize {
        match self {
            PendingOp::Deposit { .. } => 200, // commitment + redeemer overhead
            PendingOp::Transfer {
                proof,
                nullifiers,
                output_commitments,
                ..
            } => proof.len() + nullifiers.len() * 32 + output_commitments.len() * 32 + 100,
            PendingOp::Withdraw {
                proof,
                nullifiers,
                change_commitments,
                destination_address,
                ..
            } => {
                proof.len()
                    + nullifiers.len() * 32
                    + change_commitments.len() * 32
                    + destination_address.len()
                    + 100
            }
        }
    }

    /// Total proof bytes in this operation.
    fn proof_bytes(&self) -> usize {
        match self {
            PendingOp::Deposit { .. } => 0,
            PendingOp::Transfer { proof, .. } => proof.len(),
            PendingOp::Withdraw { proof, .. } => proof.len(),
        }
    }
}

/// Transaction batcher that collects operations and produces consolidated transactions.
pub struct TxBatcher {
    /// Queue of pending operations.
    pending: VecDeque<PendingOp>,
    /// Pool validator address.
    pool_validator_addr: String,
    /// Nullifier validator address.
    nullifier_validator_addr: String,
}

impl TxBatcher {
    pub fn new(pool_validator_addr: String, nullifier_validator_addr: String) -> Self {
        Self {
            pending: VecDeque::new(),
            pool_validator_addr,
            nullifier_validator_addr,
        }
    }

    /// Submit a new operation to the batcher.
    pub fn submit(&mut self, op: PendingOp) {
        self.pending.push_back(op);
    }

    /// Number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drain a batch of operations that fit within transaction limits.
    ///
    /// Returns the operations to include in the next batch, respecting
    /// both count and size constraints. Operations are processed FIFO.
    pub fn drain_batch(&mut self) -> Vec<PendingOp> {
        let mut batch = Vec::new();
        let mut total_proof_bytes = 0usize;

        while let Some(op) = self.pending.front() {
            if batch.len() >= MAX_BATCH_SIZE {
                break;
            }
            let proof_size = op.proof_bytes();
            if total_proof_bytes + proof_size > MAX_BATCH_PROOF_BYTES && !batch.is_empty() {
                break; // Would exceed proof limit, but allow single large op
            }
            total_proof_bytes += proof_size;
            batch.push(self.pending.pop_front().unwrap());
        }

        batch
    }

    /// Build a consolidated transaction from a batch of operations.
    ///
    /// This creates a single Cardano transaction that:
    /// 1. Spends the pool UTXO once (input)
    /// 2. Applies all batch operations to the pool state
    /// 3. Produces a new pool UTXO with the final state (output)
    /// 4. Creates nullifier UTXOs for all nullifiers in the batch
    pub fn build_batch_tx(
        &self,
        batch: &[PendingOp],
        pool_utxo: UtxoRef,
        current_pool_datum: &PoolDatum,
    ) -> BatchResult {
        if batch.is_empty() {
            return BatchResult {
                tx: CardanoTxBuilder::new(),
                new_pool_datum: current_pool_datum.clone(),
                nullifier_count: 0,
                total_deposit: 0,
                total_withdrawal: 0,
            };
        }

        let mut new_datum = current_pool_datum.clone();
        let mut all_nullifiers = Vec::new();
        let mut all_proofs = Vec::new();
        let mut total_deposit: u64 = 0;
        let mut total_withdrawal: u64 = 0;
        let mut all_deposit_redeemers = Vec::new();
        let mut all_transfer_redeemers = Vec::new();
        let mut all_withdraw_redeemers = Vec::new();

        for op in batch {
            match op {
                PendingOp::Deposit {
                    commitment,
                    amount,
                    asset_id,
                } => {
                    new_datum.note_count += 1;
                    total_deposit += amount;
                    all_deposit_redeemers.push(DepositRedeemer {
                        commitment: *commitment,
                        amount: *amount,
                        asset_id: *asset_id,
                    });
                }
                PendingOp::Transfer {
                    proof,
                    merkle_root,
                    nullifiers,
                    output_commitments,
                    domain_chain_id,
                    domain_app_id,
                } => {
                    new_datum.note_count += output_commitments.len() as u64;
                    for nf in nullifiers {
                        all_nullifiers.push(NullifierDatum {
                            nullifier: *nf,
                            epoch: new_datum.current_epoch,
                            domain_chain_id: *domain_chain_id,
                            domain_app_id: *domain_app_id,
                        });
                    }
                    all_proofs.push(proof.clone());
                    all_transfer_redeemers.push(TransferRedeemer {
                        proof: proof.clone(),
                        merkle_root: *merkle_root,
                        nullifiers: nullifiers.clone(),
                        output_commitments: output_commitments.clone(),
                        domain_chain_id: *domain_chain_id,
                        domain_app_id: *domain_app_id,
                    });
                }
                PendingOp::Withdraw {
                    proof,
                    merkle_root,
                    nullifiers,
                    change_commitments,
                    exit_value,
                    destination_address,
                } => {
                    new_datum.note_count += change_commitments.len() as u64;
                    total_withdrawal += exit_value;
                    for nf in nullifiers {
                        all_nullifiers.push(NullifierDatum {
                            nullifier: *nf,
                            epoch: new_datum.current_epoch,
                            domain_chain_id: 0,
                            domain_app_id: 0,
                        });
                    }
                    all_proofs.push(proof.clone());
                    all_withdraw_redeemers.push(WithdrawRedeemer {
                        proof: proof.clone(),
                        merkle_root: *merkle_root,
                        nullifiers: nullifiers.clone(),
                        change_commitments: change_commitments.clone(),
                        exit_value: *exit_value,
                        destination_address: destination_address.clone(),
                    });
                }
            }
        }

        // Build the consolidated batch redeemer
        let batch_redeemer = build_batch_redeemer(
            &all_deposit_redeemers,
            &all_transfer_redeemers,
            &all_withdraw_redeemers,
        );

        // Build the transaction
        let mut builder = CardanoTxBuilder::new().add_input(pool_utxo, Some(batch_redeemer));

        // Pool continuing output
        let pool_value = 2_000_000u64 + total_deposit - total_withdrawal;
        builder = builder.add_output(
            self.pool_validator_addr.clone(),
            pool_value,
            Some(new_datum.to_plutus_data()),
        );

        // Nullifier outputs
        for nf_datum in &all_nullifiers {
            builder = builder.add_output(
                self.nullifier_validator_addr.clone(),
                1_500_000,
                Some(nf_datum.to_plutus_data()),
            );
        }

        // Attach combined proof data as metadata
        if !all_proofs.is_empty() {
            let metadata: Vec<u8> = all_proofs.into_iter().flatten().collect();
            builder = builder.set_metadata(metadata);
        }

        BatchResult {
            tx: builder,
            new_pool_datum: new_datum,
            nullifier_count: all_nullifiers.len(),
            total_deposit,
            total_withdrawal,
        }
    }
}

/// Result of building a batch transaction.
pub struct BatchResult {
    /// The constructed transaction builder.
    pub tx: CardanoTxBuilder,
    /// The new pool datum after applying all operations.
    pub new_pool_datum: PoolDatum,
    /// Number of nullifier UTXOs created.
    pub nullifier_count: usize,
    /// Total ADA deposited in this batch.
    pub total_deposit: u64,
    /// Total ADA withdrawn in this batch.
    pub total_withdrawal: u64,
}

/// Build a batch redeemer that encodes all operations as a Plutus data constructor.
///
/// Format: Constr(3, [deposits_list, transfers_list, withdraws_list])
fn build_batch_redeemer(
    deposits: &[DepositRedeemer],
    transfers: &[TransferRedeemer],
    withdraws: &[WithdrawRedeemer],
) -> super::datum::PlutusData {
    use super::datum::PlutusData;

    PlutusData::Constr {
        tag: 3, // Batch variant (after Deposit=0, Transfer=1, Withdraw=2)
        fields: vec![
            PlutusData::List(deposits.iter().map(|d| d.to_plutus_data()).collect()),
            PlutusData::List(transfers.iter().map(|t| t.to_plutus_data()).collect()),
            PlutusData::List(withdraws.iter().map(|w| w.to_plutus_data()).collect()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool_datum() -> PoolDatum {
        PoolDatum {
            merkle_root: [0xAA; 32],
            note_count: 10,
            current_epoch: 3,
            pool_nft_policy: [0xBB; 28],
            admin_pkh: [0xCC; 28],
            vk_hash: [0x00; 32],
            nullifier_registry_hash: [0xDD; 28],
        }
    }

    #[test]
    fn batcher_submit_and_count() {
        let mut batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());
        assert_eq!(batcher.pending_count(), 0);

        batcher.submit(PendingOp::Deposit {
            commitment: [1u8; 32],
            amount: 5_000_000,
            asset_id: 0,
        });
        assert_eq!(batcher.pending_count(), 1);

        batcher.submit(PendingOp::Deposit {
            commitment: [2u8; 32],
            amount: 3_000_000,
            asset_id: 0,
        });
        assert_eq!(batcher.pending_count(), 2);
    }

    #[test]
    fn drain_batch_respects_max_size() {
        let mut batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());

        // Submit more than MAX_BATCH_SIZE operations
        for i in 0..(MAX_BATCH_SIZE + 3) {
            batcher.submit(PendingOp::Deposit {
                commitment: [i as u8; 32],
                amount: 1_000_000,
                asset_id: 0,
            });
        }

        let batch = batcher.drain_batch();
        assert_eq!(batch.len(), MAX_BATCH_SIZE);
        assert_eq!(batcher.pending_count(), 3);
    }

    #[test]
    fn drain_batch_respects_proof_limit() {
        let mut batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());

        // Each transfer has a large proof
        for i in 0..5 {
            batcher.submit(PendingOp::Transfer {
                proof: vec![0u8; 4000], // 4KB each, limit is 12KB
                merkle_root: [0xAA; 32],
                nullifiers: vec![[i as u8; 32]],
                output_commitments: vec![[i as u8; 32]],
                domain_chain_id: 1,
                domain_app_id: 1,
            });
        }

        let batch = batcher.drain_batch();
        // Should get 3 (3 * 4000 = 12000 ≤ 12288), 4th would exceed
        assert_eq!(batch.len(), 3);
        assert_eq!(batcher.pending_count(), 2);
    }

    #[test]
    fn build_batch_tx_deposits_only() {
        let batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());
        let pool_datum = test_pool_datum();
        let pool_utxo = UtxoRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };

        let batch = vec![
            PendingOp::Deposit {
                commitment: [1u8; 32],
                amount: 5_000_000,
                asset_id: 0,
            },
            PendingOp::Deposit {
                commitment: [2u8; 32],
                amount: 3_000_000,
                asset_id: 0,
            },
        ];

        let result = batcher.build_batch_tx(&batch, pool_utxo, &pool_datum);
        assert_eq!(result.total_deposit, 8_000_000);
        assert_eq!(result.total_withdrawal, 0);
        assert_eq!(result.nullifier_count, 0);
        assert_eq!(result.new_pool_datum.note_count, 12); // 10 + 2
    }

    #[test]
    fn build_batch_tx_mixed_operations() {
        let batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());
        let pool_datum = test_pool_datum();
        let pool_utxo = UtxoRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };

        let batch = vec![
            PendingOp::Deposit {
                commitment: [1u8; 32],
                amount: 10_000_000,
                asset_id: 0,
            },
            PendingOp::Transfer {
                proof: vec![0xAB; 128],
                merkle_root: [0xAA; 32],
                nullifiers: vec![[0x11; 32], [0x22; 32]],
                output_commitments: vec![[0x33; 32], [0x44; 32]],
                domain_chain_id: 1,
                domain_app_id: 1,
            },
            PendingOp::Withdraw {
                proof: vec![0xCD; 128],
                merkle_root: [0xAA; 32],
                nullifiers: vec![[0x55; 32]],
                change_commitments: vec![[0x66; 32]],
                exit_value: 3_000_000,
                destination_address: vec![0xDE; 28],
            },
        ];

        let result = batcher.build_batch_tx(&batch, pool_utxo, &pool_datum);
        assert_eq!(result.total_deposit, 10_000_000);
        assert_eq!(result.total_withdrawal, 3_000_000);
        assert_eq!(result.nullifier_count, 3); // 2 from transfer + 1 from withdraw
        assert_eq!(result.new_pool_datum.note_count, 14); // 10 + 1 deposit + 2 transfer outputs + 1 withdraw change
    }

    #[test]
    fn build_batch_tx_serializes_to_cbor() {
        let batcher = TxBatcher::new("00".repeat(28), "01".repeat(28));
        let pool_datum = test_pool_datum();
        let pool_utxo = UtxoRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };

        let batch = vec![PendingOp::Deposit {
            commitment: [1u8; 32],
            amount: 5_000_000,
            asset_id: 0,
        }];

        let result = batcher.build_batch_tx(&batch, pool_utxo, &pool_datum);
        let cbor = result.tx.serialize();

        // Should produce valid CBOR (starts with map header)
        assert!(!cbor.is_empty());
        // CBOR map starts with 0xa_ or 0xb_
        assert!(
            cbor[0] & 0xe0 == 0xa0,
            "First byte should be a CBOR map header"
        );
    }

    #[test]
    fn empty_batch_produces_empty_result() {
        let batcher = TxBatcher::new("pool_addr".into(), "nullifier_addr".into());
        let pool_datum = test_pool_datum();
        let pool_utxo = UtxoRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };

        let result = batcher.build_batch_tx(&[], pool_utxo, &pool_datum);
        assert_eq!(result.nullifier_count, 0);
        assert_eq!(result.total_deposit, 0);
        assert_eq!(result.total_withdrawal, 0);
    }

    #[test]
    fn pending_op_estimated_size() {
        let deposit = PendingOp::Deposit {
            commitment: [0; 32],
            amount: 1_000_000,
            asset_id: 0,
        };
        assert!(deposit.estimated_size() > 0);

        let transfer = PendingOp::Transfer {
            proof: vec![0; 2048],
            merkle_root: [0; 32],
            nullifiers: vec![[0; 32]; 2],
            output_commitments: vec![[0; 32]; 2],
            domain_chain_id: 1,
            domain_app_id: 1,
        };
        assert!(transfer.estimated_size() > deposit.estimated_size());
    }
}
