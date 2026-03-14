use serde::{Deserialize, Serialize};

/// Fixed-size proof envelope for metadata resistance.
///
/// All proofs are padded to exactly `ENVELOPE_SIZE` bytes before transmission,
/// preventing observers from distinguishing proof types (transfer vs withdraw)
/// by size analysis.
///
/// The actual proof length is stored inside the padded data as a 4-byte
/// little-endian prefix, so the serialized representation is always exactly
/// `ENVELOPE_SIZE` bytes with no separate length field that could leak metadata.
pub const ENVELOPE_SIZE: usize = 2048;

/// Maximum proof payload: envelope minus the 4-byte length prefix.
const MAX_PAYLOAD: usize = ENVELOPE_SIZE - 4;

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    /// Padded proof bytes (always ENVELOPE_SIZE).
    /// Layout: [real_len as u32 LE (4 bytes)] [proof bytes] [random padding]
    data: Vec<u8>,
}

impl ProofEnvelope {
    /// Wrap proof bytes into a fixed-size envelope.
    pub fn wrap(proof_bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if proof_bytes.len() > MAX_PAYLOAD {
            return Err(EnvelopeError::ProofTooLarge {
                size: proof_bytes.len(),
                max: MAX_PAYLOAD,
            });
        }
        let mut data = vec![0u8; ENVELOPE_SIZE];
        // Encode the real length as a 4-byte LE prefix inside the envelope
        let len_bytes = (proof_bytes.len() as u32).to_le_bytes();
        data[..4].copy_from_slice(&len_bytes);
        data[4..4 + proof_bytes.len()].copy_from_slice(proof_bytes);
        // Fill remainder with cryptographic randomness to prevent padding oracle attacks
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut data[4 + proof_bytes.len()..]);
        Ok(Self { data })
    }

    /// Extract the actual proof bytes from the envelope.
    pub fn unwrap(&self) -> &[u8] {
        let real_len = self.real_len();
        &self.data[4..4 + real_len]
    }

    /// Envelope is always the same size regardless of proof type.
    pub fn size(&self) -> usize {
        ENVELOPE_SIZE
    }

    /// Read the embedded proof length (not exposed publicly).
    fn real_len(&self) -> usize {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[..4]);
        u32::from_le_bytes(buf) as usize
    }
}

impl std::fmt::Debug for ProofEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally omit any length info — only show constant envelope size
        f.debug_struct("ProofEnvelope")
            .field("size", &ENVELOPE_SIZE)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("proof too large: {size} bytes (max {max})")]
    ProofTooLarge { size: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let proof = vec![1u8, 2, 3, 4, 5];
        let env = ProofEnvelope::wrap(&proof).unwrap();
        assert_eq!(env.size(), ENVELOPE_SIZE);
        assert_eq!(env.unwrap(), &proof[..]);
    }

    #[test]
    fn envelope_fixed_size() {
        let small = ProofEnvelope::wrap(&[1u8; 100]).unwrap();
        let large = ProofEnvelope::wrap(&[2u8; 1500]).unwrap();
        assert_eq!(small.size(), large.size());
    }

    #[test]
    fn envelope_rejects_oversized() {
        let too_big = vec![0u8; MAX_PAYLOAD + 1];
        assert!(ProofEnvelope::wrap(&too_big).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn envelope_roundtrip_any_size(len in 0usize..=MAX_PAYLOAD) {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let env = ProofEnvelope::wrap(&data).unwrap();
            prop_assert_eq!(env.size(), ENVELOPE_SIZE);
            prop_assert_eq!(env.unwrap(), &data[..]);
        }

        #[test]
        fn envelope_rejects_any_oversized(extra in 1usize..1024) {
            let data = vec![0u8; MAX_PAYLOAD + extra];
            prop_assert!(ProofEnvelope::wrap(&data).is_err());
        }

        #[test]
        fn envelope_constant_size(len1 in 0usize..=MAX_PAYLOAD, len2 in 0usize..=MAX_PAYLOAD) {
            let d1: Vec<u8> = vec![0xAA; len1];
            let d2: Vec<u8> = vec![0xBB; len2];
            let e1 = ProofEnvelope::wrap(&d1).unwrap();
            let e2 = ProofEnvelope::wrap(&d2).unwrap();
            prop_assert_eq!(e1.size(), e2.size(), "all envelopes must be same size");
        }
    }
}
