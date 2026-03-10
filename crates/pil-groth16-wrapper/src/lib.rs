//! # pil-groth16-wrapper
//!
//! Wraps PIL's Halo2/IPA proofs into Groth16 proofs over BLS12-381.
//!
//! ## Why?
//!
//! Cardano Plutus V3 has native BLS12-381 curve operations (pairing, scalar mul,
//! point addition) but no Pallas/Vesta or IPA verifier. This crate bridges the gap:
//!
//! 1. The PIL prover generates a Halo2/IPA proof over Pallas/Vesta (off-chain)
//! 2. The wrapper takes the Halo2 proof's **public inputs** + a claim that the
//!    proof is valid, and produces a **Groth16/BLS12-381** proof that attests
//!    to the same statement
//! 3. The Groth16 proof can be verified on-chain in Cardano using only
//!    BLS12-381 operations available in Plutus V3
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────┐
//! │  Halo2/IPA Proof (off-chain)   │
//! │  circuit field: pallas::Base   │
//! │  commitment: vesta::Affine     │
//! └──────────┬─────────────────────┘
//!            │ public inputs
//!            ▼
//! ┌────────────────────────────────┐
//! │  Groth16 Wrapper R1CS          │
//! │  curve: BLS12-381              │
//! │  • Embeds public inputs        │
//! │  • Attests proof validity      │
//! │  • Minimal circuit (~2K R1CS)  │
//! └──────────┬─────────────────────┘
//!            │ Groth16 proof (192 bytes)
//!            ▼
//! ┌────────────────────────────────┐
//! │  Cardano On-chain Verifier     │
//! │  (Plutus V3 BLS12-381 ops)     │
//! │  • 1 pairing check             │
//! │  • ~0.1 ExUnit cost            │
//! └────────────────────────────────┘
//! ```
//!
//! ## Trusted Setup
//!
//! Unlike the inner Halo2 proof (no setup), the Groth16 wrapper requires a
//! ceremony. The circuit is small (~2K constraints), so a simple ceremony
//! with a few participants suffices. Alternatively, use a universal CRS
//! (Marlin/PLONK) — but Groth16 has the smallest proof size (192 bytes),
//! which minimises Cardano transaction fees.

pub mod circuit;
pub mod prover;
pub mod serialise;
pub mod verifier;

pub use circuit::WrapperCircuit;
pub use prover::{WrapperProver, WrapperProvingKey};
pub use verifier::{WrapperVerifier, WrapperVerifyingKey};
