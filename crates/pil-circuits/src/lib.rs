//! # pil-circuits
//!
//! Halo2 ZK circuits for the Privacy Interoperability Layer.
//!
//! ## Circuits
//!
//! - **TransferCircuit** (k=13): 2-in-2-out private transfer with fee enforcement
//! - **WithdrawCircuit** (k=13): 2-in-2-out withdrawal with public exit value
//! - **WealthProofCircuit** (k=15): Prove balance exceeds threshold without revealing amount
//!
//! All circuits use the Pallas/Vesta curve cycle with IPA commitment scheme
//! (no trusted setup required).

pub mod gadgets;
pub mod transfer;
pub mod wealth;
pub mod withdraw;

pub use transfer::TransferCircuit;
pub use wealth::WealthProofCircuit;
pub use withdraw::WithdrawCircuit;
