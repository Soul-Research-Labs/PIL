//! # pil-client
//!
//! Client wallet for PIL. Manages spending keys, tracks owned notes,
//! provides coin selection for transfers, and wallet encryption/backup.

use pil_note::{keys::SpendingKey, note::Note};
use pil_primitives::types::{Base, Commitment, Nullifier};
use serde::{Deserialize, Serialize};

/// A wallet entry: a note and its metadata.
#[derive(Debug, Clone)]
pub struct WalletNote {
    pub note: Note,
    pub leaf_index: u64,
    pub spent: bool,
}

/// Transaction history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxRecord {
    Deposit { value: u64, asset_id: u64, leaf_index: u64 },
    Send { value: u64, asset_id: u64, recipient_owner: String },
    Withdraw { value: u64, asset_id: u64 },
}

/// The PIL client wallet.
#[derive(Clone)]
pub struct Wallet {
    /// Owner identity (derived from spending key).
    owner: String,
    /// Tracked notes (both spent and unspent).
    notes: Vec<WalletNote>,
    /// Transaction history.
    history: Vec<TxRecord>,
}

impl Wallet {
    pub fn new(owner_hex: String) -> Self {
        Self {
            owner: owner_hex,
            notes: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Add a note to the wallet.
    pub fn add_note(&mut self, note: Note, leaf_index: u64) {
        self.notes.push(WalletNote {
            note,
            leaf_index,
            spent: false,
        });
    }

    /// Mark a note as spent.
    pub fn mark_spent(&mut self, leaf_index: u64) {
        if let Some(entry) = self.notes.iter_mut().find(|n| n.leaf_index == leaf_index) {
            entry.spent = true;
        }
    }

    /// Get unspent notes.
    pub fn unspent_notes(&self) -> Vec<&WalletNote> {
        self.notes.iter().filter(|n| !n.spent).collect()
    }

    /// Get total balance across all unspent notes.
    pub fn balance(&self) -> u64 {
        self.unspent_notes().iter().map(|n| n.note.value).sum()
    }

    /// Get balance for a specific asset.
    pub fn balance_for_asset(&self, asset_id: u64) -> u64 {
        self.unspent_notes()
            .iter()
            .filter(|n| n.note.asset_id == asset_id)
            .map(|n| n.note.value)
            .sum()
    }

    /// Coin selection: pick notes that sum to at least `target`.
    pub fn select_notes(&self, target: u64, asset_id: u64) -> Result<Vec<&WalletNote>, WalletError> {
        let mut candidates: Vec<_> = self
            .unspent_notes()
            .into_iter()
            .filter(|n| n.note.asset_id == asset_id)
            .collect();

        // Sort by value descending for largest-first selection
        candidates.sort_by(|a, b| b.note.value.cmp(&a.note.value));

        let mut selected = Vec::new();
        let mut accumulated = 0u64;

        for note in candidates {
            if accumulated >= target {
                break;
            }
            accumulated += note.note.value;
            selected.push(note);
        }

        if accumulated < target {
            return Err(WalletError::InsufficientBalance {
                available: accumulated,
                required: target,
            });
        }

        Ok(selected)
    }

    /// Record a transaction in history.
    pub fn record_tx(&mut self, record: TxRecord) {
        self.history.push(record);
    }

    /// Get transaction history.
    pub fn history(&self) -> &[TxRecord] {
        &self.history
    }

    /// Get owner identity.
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("insufficient balance: {available} available, {required} required")]
    InsufficientBalance { available: u64, required: u64 },
    #[error("encryption error: {0}")]
    Encryption(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pil_note::note::Note;

    #[test]
    fn wallet_balance_tracking() {
        let mut wallet = Wallet::new("test_owner".to_string());
        let note = Note::with_randomness(100, Base::from(1u64), 0, Base::from(1u64));
        wallet.add_note(note, 0);
        assert_eq!(wallet.balance(), 100);

        wallet.mark_spent(0);
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn coin_selection() {
        let mut wallet = Wallet::new("test".to_string());
        wallet.add_note(
            Note::with_randomness(50, Base::from(1u64), 0, Base::from(1u64)),
            0,
        );
        wallet.add_note(
            Note::with_randomness(30, Base::from(1u64), 0, Base::from(2u64)),
            1,
        );
        wallet.add_note(
            Note::with_randomness(80, Base::from(1u64), 0, Base::from(3u64)),
            2,
        );

        let selected = wallet.select_notes(70, 0).unwrap();
        assert_eq!(selected[0].note.value, 80); // Largest first
    }
}
