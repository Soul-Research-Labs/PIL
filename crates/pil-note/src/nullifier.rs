use pil_primitives::{
    domain::DomainSeparator,
    hash::poseidon_hash2,
    types::{Base, Commitment, Nullifier},
};

/// Derive a V1 nullifier (single-chain): Poseidon(spending_key, commitment).
///
/// Used when operating within a single chain without cross-chain concerns.
pub fn derive_nullifier_v1(spending_key: Base, commitment: Commitment) -> Nullifier {
    Nullifier(poseidon_hash2(spending_key, commitment.0))
}

/// Derive a V2 nullifier (cross-chain): Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id)).
///
/// Domain-separated nullifiers prevent double-spend attacks across chains.
/// A note spent on Cardano cannot be replayed on Cosmos because the domain tags differ.
pub fn derive_nullifier_v2(
    spending_key: Base,
    commitment: Commitment,
    domain: &DomainSeparator,
) -> Nullifier {
    let inner = poseidon_hash2(spending_key, commitment.0);
    let domain_tag = domain.to_domain_tag();
    Nullifier(poseidon_hash2(inner, domain_tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pil_primitives::domain::ChainDomain;

    #[test]
    fn v1_nullifier_deterministic() {
        let sk = Base::from(12345u64);
        let cm = Commitment(Base::from(67890u64));
        let n1 = derive_nullifier_v1(sk, cm);
        let n2 = derive_nullifier_v1(sk, cm);
        assert_eq!(n1, n2);
    }

    #[test]
    fn v2_nullifier_domain_isolation() {
        let sk = Base::from(12345u64);
        let cm = Commitment(Base::from(67890u64));

        let cardano_domain = DomainSeparator::new(ChainDomain::CardanoMainnet, 1);
        let cosmos_domain = DomainSeparator::new(ChainDomain::CosmosHub, 1);

        let n_cardano = derive_nullifier_v2(sk, cm, &cardano_domain);
        let n_cosmos = derive_nullifier_v2(sk, cm, &cosmos_domain);

        // Same note, different chains → different nullifiers
        assert_ne!(n_cardano, n_cosmos);
    }

    #[test]
    fn v1_and_v2_differ() {
        let sk = Base::from(12345u64);
        let cm = Commitment(Base::from(67890u64));
        let domain = DomainSeparator::new(ChainDomain::CardanoMainnet, 1);

        let n_v1 = derive_nullifier_v1(sk, cm);
        let n_v2 = derive_nullifier_v2(sk, cm, &domain);
        assert_ne!(n_v1, n_v2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use pil_primitives::domain::ChainDomain;
    use proptest::prelude::*;

    fn arb_base() -> impl Strategy<Value = Base> {
        any::<u64>().prop_map(Base::from)
    }

    proptest! {
        #[test]
        fn v1_deterministic(sk in arb_base(), cm in arb_base()) {
            let commitment = Commitment(cm);
            let n1 = derive_nullifier_v1(sk, commitment);
            let n2 = derive_nullifier_v1(sk, commitment);
            prop_assert_eq!(n1, n2);
        }

        #[test]
        fn v2_cross_chain_isolation(sk in arb_base(), cm in arb_base(), app_id in 0u32..100) {
            let commitment = Commitment(cm);
            let d_cardano = DomainSeparator::new(ChainDomain::CardanoMainnet, app_id);
            let d_cosmos = DomainSeparator::new(ChainDomain::CosmosHub, app_id);
            let n1 = derive_nullifier_v2(sk, commitment, &d_cardano);
            let n2 = derive_nullifier_v2(sk, commitment, &d_cosmos);
            prop_assert_ne!(n1, n2, "same note on different chains must produce different nullifiers");
        }

        #[test]
        fn v2_app_isolation(sk in arb_base(), cm in arb_base()) {
            let commitment = Commitment(cm);
            let d1 = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);
            let d2 = DomainSeparator::new(ChainDomain::CardanoMainnet, 1);
            let n1 = derive_nullifier_v2(sk, commitment, &d1);
            let n2 = derive_nullifier_v2(sk, commitment, &d2);
            prop_assert_ne!(n1, n2, "same note in different apps must produce different nullifiers");
        }

        #[test]
        fn different_keys_different_nullifiers(sk1 in 1u64..u64::MAX, sk2 in 1u64..u64::MAX, cm in arb_base()) {
            prop_assume!(sk1 != sk2);
            let commitment = Commitment(cm);
            let n1 = derive_nullifier_v1(Base::from(sk1), commitment);
            let n2 = derive_nullifier_v1(Base::from(sk2), commitment);
            prop_assert_ne!(n1, n2, "different spending keys must produce different nullifiers");
        }
    }
}
