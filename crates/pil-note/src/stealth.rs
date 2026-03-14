use ff::Field;
use group::{prime::PrimeCurveAffine, Group};
use pasta_curves::{arithmetic::CurveAffine, pallas};
use pil_primitives::hash::poseidon_hash2;

/// Stealth address meta — the ephemeral public key sent alongside a transaction
/// so the recipient can detect and claim the note.
#[derive(Debug, Clone)]
pub struct StealthMeta {
    pub ephemeral_pk: pallas::Point,
}

/// A one-time stealth address derived via ECDH on Pallas + Poseidon.
///
/// Protocol:
/// 1. Sender picks random `r`, computes `R = r*G` (ephemeral key)
/// 2. Sender computes `shared = r * recipient_pk`
/// 3. Sender derives `one_time_owner = Poseidon(shared_x, recipient_owner)`
/// 4. Recipient scans: computes `shared = vk * R`, then checks owner derivation
#[derive(Debug, Clone)]
pub struct StealthAddress {
    /// The one-time owner identity for the note.
    pub one_time_owner: pallas::Base,
    /// Ephemeral public key (sent on-chain for recipient scanning).
    pub ephemeral_pk: pallas::Point,
}

/// Create a stealth address for sending to a recipient.
///
/// - `recipient_pk`: recipient's public key point
/// - `recipient_owner`: recipient's owner field element
///
/// Returns `None` if the recipient's public key is the identity point
/// (which would make ECDH degenerate).
pub fn stealth_send(recipient_pk: pallas::Point, recipient_owner: pallas::Base) -> Option<StealthAddress> {
    let mut rng = rand::thread_rng();
    let r = pallas::Scalar::random(&mut rng);
    let ephemeral_pk = pallas::Point::generator() * r;

    // ECDH: shared = r * recipient_pk
    let shared = recipient_pk * r;
    let shared_x = {
        use group::Curve;
        let affine = shared.to_affine();
        if bool::from(affine.is_identity()) {
            return None;
        }
        *affine.coordinates().unwrap().x()
    };

    // One-time owner = Poseidon(shared_x, recipient_owner)
    let one_time_owner = poseidon_hash2(shared_x, recipient_owner);

    Some(StealthAddress {
        one_time_owner,
        ephemeral_pk,
    })
}

/// Scan for incoming stealth payments (recipient side).
///
/// - `viewing_sk`: recipient's viewing key scalar
/// - `owner`: recipient's owner field element
/// - `ephemeral_pk`: the ephemeral public key from the transaction
///
/// Returns the one-time owner if the stealth address is for this recipient,
/// or `None` if the ECDH shared point is the identity.
pub fn stealth_receive(
    viewing_sk: pallas::Scalar,
    owner: pallas::Base,
    ephemeral_pk: pallas::Point,
) -> Option<pallas::Base> {
    // ECDH: shared = viewing_sk * ephemeral_pk
    let shared = ephemeral_pk * viewing_sk;
    let shared_x = {
        use group::Curve;
        let affine = shared.to_affine();
        if bool::from(affine.is_identity()) {
            return None;
        }
        *affine.coordinates().unwrap().x()
    };

    Some(poseidon_hash2(shared_x, owner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;

    #[test]
    fn stealth_address_roundtrip() {
        let mut rng = rand::thread_rng();
        let sk = SpendingKey::random(&mut rng);
        let owner = sk.owner();
        let vk = sk.viewing_key();

        // Sender creates stealth address using the VIEWING public key
        let stealth = stealth_send(vk.public_point(), owner)
            .expect("stealth_send should succeed with valid key");

        // Recipient scans using viewing key scalar
        let detected_owner = stealth_receive(vk.scalar(), owner, stealth.ephemeral_pk)
            .expect("stealth_receive should succeed with valid key");

        assert_eq!(stealth.one_time_owner, detected_owner);
    }
}
