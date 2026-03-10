use crate::types::Base;
use ff::Field;
use serde::{Deserialize, Serialize};

/// Chain identifiers for domain separation across supported ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ChainDomain {
    /// Cardano mainnet
    CardanoMainnet = 1,
    /// Cardano preprod testnet
    CardanoPreprod = 2,
    /// Cardano preview testnet
    CardanoPreview = 3,
    /// Cosmos Hub
    CosmosHub = 10,
    /// Osmosis
    Osmosis = 11,
    /// Neutron
    Neutron = 12,
    /// Injective
    Injective = 13,
    /// Secret Network
    SecretNetwork = 14,
    /// Celestia
    Celestia = 15,
    /// Sei
    Sei = 16,
    /// Archway
    Archway = 17,
    /// Dymension
    Dymension = 18,
    /// Stargaze
    Stargaze = 19,
    /// Akash
    Akash = 20,
    /// Juno
    Juno = 21,
    /// Custom chain (user-defined ID)
    Custom(u32) = 0xFFFF,
}

impl ChainDomain {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Custom(id) => *id,
            other => {
                // Safety: all non-Custom variants have fixed discriminants
                unsafe { *(other as *const Self as *const u32) }
            }
        }
    }

    pub fn to_field(&self) -> Base {
        Base::from(self.as_u32() as u64)
    }
}

/// Domain separator for cross-chain nullifier isolation.
///
/// Follows the pattern from ZAseon's Cross-Domain Nullifier Algebra:
/// nullifier_v2 = Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSeparator {
    pub chain: ChainDomain,
    pub app_id: u32,
}

impl DomainSeparator {
    pub fn new(chain: ChainDomain, app_id: u32) -> Self {
        Self { chain, app_id }
    }

    /// Create a domain tag field element: Poseidon(chain_id, app_id).
    pub fn to_domain_tag(&self) -> Base {
        crate::hash::poseidon_hash2(self.chain.to_field(), Base::from(self.app_id as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_chains_produce_different_domain_tags() {
        let d1 = DomainSeparator::new(ChainDomain::CardanoMainnet, 1);
        let d2 = DomainSeparator::new(ChainDomain::CosmosHub, 1);
        assert_ne!(d1.to_domain_tag(), d2.to_domain_tag());
    }

    #[test]
    fn different_apps_produce_different_domain_tags() {
        let d1 = DomainSeparator::new(ChainDomain::CardanoMainnet, 1);
        let d2 = DomainSeparator::new(ChainDomain::CardanoMainnet, 2);
        assert_ne!(d1.to_domain_tag(), d2.to_domain_tag());
    }
}
