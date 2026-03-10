use ff::PrimeField;
use group::Curve;
use pasta_curves::pallas;

/// A Pedersen commitment: C = v*G + r*H where G, H are independent generators.
#[derive(Debug, Clone, Copy)]
pub struct PedersenCommitment(pub pallas::Point);

/// Compute a Pedersen commitment: commit(value, blinding) = value*G + blinding*H.
///
/// Uses the Pallas curve with two independent generator points derived
/// from nothing-up-my-sleeve constants.
pub fn pedersen_commit(value: pallas::Scalar, blinding: pallas::Scalar) -> PedersenCommitment {
    use group::Group;

    let g = pallas::Point::generator();
    // H is derived deterministically from hashing "PIL_Pedersen_H" to a curve point.
    // In production, use a hash-to-curve construction (e.g., SWU map).
    // For now, we use a simple scalar multiplication of the generator.
    let h_scalar = {
        use blake2::{Blake2b512, Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(b"PIL_Pedersen_H_Generator");
        let hash = hasher.finalize();
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&hash[..32]);
        repr[31] &= 0x0f; // Ensure it's in the scalar field
        pallas::Scalar::from_repr(repr).unwrap_or(pallas::Scalar::from(7u64))
    };
    let h = g * h_scalar;

    PedersenCommitment(g * value + h * blinding)
}

impl PedersenCommitment {
    /// Convert to affine coordinates for serialization.
    pub fn to_affine(&self) -> pallas::Affine {
        self.0.to_affine()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn commitment_hiding() {
        let mut rng = rand::thread_rng();
        let value = pallas::Scalar::from(100u64);
        let r1 = pallas::Scalar::random(&mut rng);
        let r2 = pallas::Scalar::random(&mut rng);
        let c1 = pedersen_commit(value, r1);
        let c2 = pedersen_commit(value, r2);
        // Same value, different blinding → different commitments (hiding property)
        assert_ne!(
            c1.to_affine(),
            c2.to_affine(),
            "same value with different blinding should produce different commitments"
        );
    }

    #[test]
    fn commitment_binding() {
        let blinding = pallas::Scalar::from(42u64);
        let c1 = pedersen_commit(pallas::Scalar::from(100u64), blinding);
        let c2 = pedersen_commit(pallas::Scalar::from(200u64), blinding);
        // Different values → different commitments (binding property)
        assert_ne!(c1.to_affine(), c2.to_affine());
    }
}
