//! # pil-client
//!
//! Client wallet for PIL. Manages spending keys, tracks owned notes,
//! provides coin selection for transfers, and wallet encryption/backup.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use pil_note::note::Note;
use pil_primitives::types::Base;
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
    Deposit {
        value: u64,
        asset_id: u64,
        leaf_index: u64,
    },
    Send {
        value: u64,
        asset_id: u64,
        recipient_owner: String,
    },
    Withdraw {
        value: u64,
        asset_id: u64,
    },
}

/// Serializable wallet snapshot for persistence.
#[derive(Serialize, Deserialize)]
struct WalletSnapshot {
    owner: String,
    notes: Vec<NoteSnapshot>,
    history: Vec<TxRecord>,
}

#[derive(Serialize, Deserialize)]
struct NoteSnapshot {
    value: u64,
    owner_hex: String,
    asset_id: u64,
    randomness_hex: String,
    leaf_index: u64,
    spent: bool,
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
    pub fn select_notes(
        &self,
        target: u64,
        asset_id: u64,
    ) -> Result<Vec<&WalletNote>, WalletError> {
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

    // -----------------------------------------------------------------------
    // Encryption & persistence
    // -----------------------------------------------------------------------

    /// Serialize the wallet to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, WalletError> {
        use ff::PrimeField;
        let snap = WalletSnapshot {
            owner: self.owner.clone(),
            notes: self
                .notes
                .iter()
                .map(|wn| NoteSnapshot {
                    value: wn.note.value,
                    owner_hex: hex::encode(wn.note.owner.to_repr().as_ref()),
                    asset_id: wn.note.asset_id,
                    randomness_hex: hex::encode(wn.note.randomness.to_repr().as_ref()),
                    leaf_index: wn.leaf_index,
                    spent: wn.spent,
                })
                .collect(),
            history: self.history.clone(),
        };
        serde_json::to_vec(&snap).map_err(|e| WalletError::Encryption(e.to_string()))
    }

    /// Deserialize a wallet from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, WalletError> {
        let snap: WalletSnapshot =
            serde_json::from_slice(data).map_err(|e| WalletError::Encryption(e.to_string()))?;
        let notes = snap
            .notes
            .into_iter()
            .map(|ns| {
                let owner = field_from_hex(&ns.owner_hex)?;
                let randomness = field_from_hex(&ns.randomness_hex)?;
                Ok(WalletNote {
                    note: Note::with_randomness(ns.value, owner, ns.asset_id, randomness),
                    leaf_index: ns.leaf_index,
                    spent: ns.spent,
                })
            })
            .collect::<Result<Vec<_>, WalletError>>()?;

        Ok(Self {
            owner: snap.owner,
            notes,
            history: snap.history,
        })
    }

    /// Encrypt the wallet with a password using Argon2 + AES-256-GCM.
    pub fn encrypt(&self, password: &[u8]) -> Result<Vec<u8>, WalletError> {
        let plaintext = self.to_json()?;

        // Derive key with Argon2
        let salt: [u8; 16] = rand::random();
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password, &salt, &mut key)
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Encrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Encode: salt (16) || nonce (12) || ciphertext
        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a wallet from encrypted bytes and password.
    pub fn decrypt(encrypted: &[u8], password: &[u8]) -> Result<Self, WalletError> {
        if encrypted.len() < 28 {
            return Err(WalletError::Encryption("data too short".into()));
        }
        let salt = &encrypted[..16];
        let nonce_bytes = &encrypted[16..28];
        let ciphertext = &encrypted[28..];

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| WalletError::Encryption("decryption failed (wrong password?)".into()))?;

        Self::from_json(&plaintext)
    }

    /// Save wallet encrypted to a file path.
    pub fn save_encrypted(
        &self,
        path: &std::path::Path,
        password: &[u8],
    ) -> Result<(), WalletError> {
        let data = self.encrypt(password)?;
        std::fs::write(path, data).map_err(|e| WalletError::Io(e.to_string()))
    }

    /// Load wallet from an encrypted file.
    pub fn load_encrypted(path: &std::path::Path, password: &[u8]) -> Result<Self, WalletError> {
        let data = std::fs::read(path).map_err(|e| WalletError::Io(e.to_string()))?;
        Self::decrypt(&data, password)
    }
}

fn field_from_hex(hex_str: &str) -> Result<Base, WalletError> {
    use ff::PrimeField;
    let bytes = hex::decode(hex_str)
        .map_err(|_| WalletError::Encryption(format!("invalid hex: {hex_str}")))?;
    if bytes.len() != 32 {
        return Err(WalletError::Encryption(
            "field element must be 32 bytes".into(),
        ));
    }
    let mut repr = <Base as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::from(Base::from_repr(repr))
        .ok_or_else(|| WalletError::Encryption("invalid field element".into()))
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("insufficient balance: {available} available, {required} required")]
    InsufficientBalance { available: u64, required: u64 },
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("I/O error: {0}")]
    Io(String),
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

    #[test]
    fn json_roundtrip() {
        let mut wallet = Wallet::new("test_owner".to_string());
        wallet.add_note(
            Note::with_randomness(42, Base::from(7u64), 0, Base::from(99u64)),
            5,
        );
        wallet.record_tx(TxRecord::Deposit {
            value: 42,
            asset_id: 0,
            leaf_index: 5,
        });

        let json = wallet.to_json().unwrap();
        let restored = Wallet::from_json(&json).unwrap();
        assert_eq!(restored.owner(), "test_owner");
        assert_eq!(restored.balance(), 42);
        assert_eq!(restored.history().len(), 1);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut wallet = Wallet::new("enc_test".to_string());
        wallet.add_note(
            Note::with_randomness(1000, Base::from(1u64), 0, Base::from(1u64)),
            0,
        );

        let password = b"strong_passphrase_123";
        let encrypted = wallet.encrypt(password).unwrap();
        let decrypted = Wallet::decrypt(&encrypted, password).unwrap();

        assert_eq!(decrypted.owner(), "enc_test");
        assert_eq!(decrypted.balance(), 1000);
    }

    #[test]
    fn wrong_password_fails() {
        let wallet = Wallet::new("test".to_string());
        let encrypted = wallet.encrypt(b"correct").unwrap();
        assert!(Wallet::decrypt(&encrypted, b"wrong").is_err());
    }

    #[test]
    fn truncated_encrypted_data_fails() {
        let wallet = Wallet::new("test".to_string());
        let encrypted = wallet.encrypt(b"pass").unwrap();
        // Truncate to only salt (16 bytes) — missing nonce + ciphertext
        assert!(Wallet::decrypt(&encrypted[..16], b"pass").is_err());
        // Completely empty
        assert!(Wallet::decrypt(&[], b"pass").is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let wallet = Wallet::new("test".to_string());
        let mut encrypted = wallet.encrypt(b"pass").unwrap();
        // Flip a byte in the ciphertext portion
        if encrypted.len() > 30 {
            encrypted[30] ^= 0xFF;
        }
        assert!(Wallet::decrypt(&encrypted, b"pass").is_err());
    }

    #[test]
    fn invalid_json_in_from_json_fails() {
        assert!(Wallet::from_json(b"not valid json").is_err());
    }
}
