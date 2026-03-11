#![no_main]
use libfuzzer_sys::fuzz_target;

use ff::Field;
use pasta_curves::pallas;
use pil_tree::IncrementalMerkleTree;

type Base = pallas::Base;

fuzz_target!(|data: &[u8]| {
    // Each leaf is a u64 (8 bytes), limit to 16 leaves per run
    let num_leaves = data.len() / 8;
    if num_leaves == 0 || num_leaves > 16 {
        return;
    }

    let mut tree = IncrementalMerkleTree::new();
    let mut leaves = Vec::new();

    for i in 0..num_leaves {
        let val = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        let leaf = Base::from(val);
        let idx = tree.append(leaf).unwrap();
        assert_eq!(idx, i as u64, "leaf index must be sequential");
        leaves.push(leaf);
    }

    assert_eq!(tree.leaf_count(), num_leaves as u64);

    // Verify all authentication paths
    for (i, leaf) in leaves.iter().enumerate() {
        let path = tree.authentication_path(i as u64).unwrap();
        assert!(
            path.verify(*leaf, tree.root()),
            "authentication path must verify for leaf {}",
            i
        );

        // A wrong leaf must fail
        let wrong = Base::from(u64::MAX - i as u64);
        if wrong != *leaf {
            assert!(
                !path.verify(wrong, tree.root()),
                "wrong leaf must not verify"
            );
        }
    }
});
