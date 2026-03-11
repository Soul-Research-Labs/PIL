#![no_main]
use libfuzzer_sys::fuzz_target;

use ff::Field;
use pasta_curves::pallas;
use pil_note::{derive_nullifier_v1, derive_nullifier_v2};
use pil_primitives::{
    domain::{ChainDomain, DomainSeparator},
    types::{Base, Commitment},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let sk_val = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let cm_val = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let sk = Base::from(sk_val);
    let cm = Commitment(Base::from(cm_val));

    // V1 determinism
    let n1 = derive_nullifier_v1(sk, cm);
    let n2 = derive_nullifier_v1(sk, cm);
    assert_eq!(n1, n2, "V1 nullifier must be deterministic");

    // V2 domain isolation: Cardano vs Cosmos must differ
    let d_cardano = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);
    let d_cosmos = DomainSeparator::new(ChainDomain::CosmosHub, 0);
    let nc = derive_nullifier_v2(sk, cm, &d_cardano);
    let no = derive_nullifier_v2(sk, cm, &d_cosmos);
    assert_ne!(
        nc, no,
        "same note on different chains must produce different nullifiers"
    );

    // V1 != V2 for any domain
    let v1 = derive_nullifier_v1(sk, cm);
    let v2 = derive_nullifier_v2(sk, cm, &d_cardano);
    assert_ne!(v1, v2, "V1 and V2 nullifiers must differ");
});
