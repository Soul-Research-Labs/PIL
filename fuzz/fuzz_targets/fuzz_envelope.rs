#![no_main]
use libfuzzer_sys::fuzz_target;

use pil_primitives::envelope::ProofEnvelope;

fuzz_target!(|data: &[u8]| {
    match ProofEnvelope::wrap(data) {
        Ok(env) => {
            // Property: constant envelope size
            assert_eq!(env.size(), 2048, "envelope must always be 2048 bytes");

            // Property: roundtrip
            let unwrapped = env.unwrap();
            assert_eq!(unwrapped, data, "unwrap must return original data");
        }
        Err(_) => {
            // Rejection is only valid for oversized data
            assert!(
                data.len() > 2048,
                "wrap should only fail for data > 2048 bytes, got {}",
                data.len()
            );
        }
    }
});
