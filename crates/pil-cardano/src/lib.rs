//! # pil-cardano
//!
//! Cardano adapter for the Privacy Interoperability Layer.
//!
//! ## Architecture
//!
//! Cardano uses the Extended UTXO (eUTXO) model, which is fundamentally different
//! from account-based chains. This adapter maps PIL's privacy pool to Cardano's
//! eUTXO model:
//!
//! ### On-chain (Aiken validators)
//! - **PrivacyPoolValidator**: Validates deposits, transfers, and withdrawals
//!   by checking ZK proof verification results attached as reference inputs
//! - **NullifierValidator**: Manages the nullifier registry as a set of UTXOs
//! - **EpochValidator**: Handles epoch finalization and root publishing
//!
//! ### Off-chain (this crate)
//! - Transaction building for deposit/transfer/withdraw
//! - eUTXO coin selection for shielded notes
//! - Datum/redeemer encoding for Aiken validators
//! - Proof attachment as reference script metadata
//!
//! ### Cardano-specific Considerations
//!
//! 1. **eUTXO Mapping**: Each unspent note = one UTXO with datum containing
//!    the note commitment. The Merkle tree root is maintained as a continuing
//!    state UTXO (CIP-68 pattern).
//!
//! 2. **Plutus V3**: Supports BLS12-381 primitives and keccak-256 natively.
//!    ZK proof verification can be performed on-chain (limited by execution
//!    units) or via optimistic verification with fraud proofs.
//!
//! 3. **Native Multi-Asset**: Cardano's native token model means the privacy
//!    pool can handle ADA + any Cardano native token (CNT) natively, without
//!    wrapping. Asset IDs map directly to policy_id + asset_name.
//!
//! 4. **Hydra L2**: For high-throughput private transfers, the privacy pool
//!    can operate inside a Hydra head, with periodic state commitments
//!    to L1 for finality.
//!
//! 5. **Mithril**: Light client proofs via Mithril allow other chains
//!    (Cosmos via IBC) to verify Cardano state without running a full node.

pub mod datum;
pub mod redeemer;
pub mod transaction;
pub mod utxo;
pub mod validator;

pub use datum::{NullifierDatum, PoolDatum};
pub use redeemer::{DepositRedeemer, PoolRedeemer, TransferRedeemer, WithdrawRedeemer};
pub use transaction::CardanoTxBuilder;
pub use validator::CardanoValidatorSpec;
