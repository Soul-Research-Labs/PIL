//! Cardano eUTXO model types and helpers.

use serde::{Deserialize, Serialize};

/// Simplified Cardano UTXO reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UtxoRef {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Output index within the transaction.
    pub output_index: u32,
}

/// A Cardano UTXO with its associated datum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardanoUtxo {
    pub reference: UtxoRef,
    /// Address (Shelley bech32 encoded).
    pub address: String,
    /// Lovelace value.
    pub lovelace: u64,
    /// Native tokens: (policy_id, asset_name) → amount.
    pub tokens: Vec<(String, String, u64)>,
    /// Inline datum (if any).
    pub datum: Option<Vec<u8>>,
    /// Datum hash (if datum is referenced by hash).
    pub datum_hash: Option<[u8; 32]>,
}

/// Coin selection for shielded note UTXOs.
///
/// Given a set of available UTXOs and a target amount, select the optimal
/// set of inputs. Uses a largest-first strategy to minimize transaction size.
pub fn coin_select(
    available: &[CardanoUtxo],
    target_lovelace: u64,
) -> Result<Vec<CardanoUtxo>, CoinSelectionError> {
    let mut sorted: Vec<_> = available.to_vec();
    sorted.sort_by(|a, b| b.lovelace.cmp(&a.lovelace));

    let mut selected = Vec::new();
    let mut accumulated = 0u64;

    for utxo in sorted {
        if accumulated >= target_lovelace {
            break;
        }
        accumulated += utxo.lovelace;
        selected.push(utxo);
    }

    if accumulated < target_lovelace {
        return Err(CoinSelectionError::InsufficientFunds {
            available: accumulated,
            required: target_lovelace,
        });
    }

    Ok(selected)
}

#[derive(Debug, thiserror::Error)]
pub enum CoinSelectionError {
    #[error("insufficient funds: {available} lovelace available, {required} required")]
    InsufficientFunds { available: u64, required: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(lovelace: u64) -> CardanoUtxo {
        CardanoUtxo {
            reference: UtxoRef {
                tx_hash: [0; 32],
                output_index: 0,
            },
            address: "addr_test1...".to_string(),
            lovelace,
            tokens: vec![],
            datum: None,
            datum_hash: None,
        }
    }

    #[test]
    fn coin_selection_basic() {
        let utxos = vec![make_utxo(50), make_utxo(30), make_utxo(100)];
        let selected = coin_select(&utxos, 80).unwrap();
        // Should select the 100 lovelace UTXO first (largest-first)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].lovelace, 100);
    }

    #[test]
    fn coin_selection_insufficient() {
        let utxos = vec![make_utxo(10), make_utxo(20)];
        assert!(coin_select(&utxos, 100).is_err());
    }
}
