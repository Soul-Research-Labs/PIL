use ff::PrimeField;
use pasta_curves::pallas;
use pil_primitives::hash::poseidon_hash;
use serde::{Deserialize, Serialize};

/// Master spending key — the root secret from which all other keys are derived.
#[derive(Clone)]
pub struct SpendingKey {
    sk: pallas::Scalar,
}

/// Viewing key — allows scanning for incoming notes without spending authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKey {
    /// The viewing scalar (derived from spending key).
    #[serde(with = "scalar_serde")]
    vk: pallas::Scalar,
    /// The public viewing point (vk * G).
    #[serde(with = "point_serde")]
    pk: pallas::Point,
}

impl SpendingKey {
    /// Generate a random spending key.
    pub fn random(rng: &mut impl rand::RngCore) -> Self {
        use ff::Field;
        Self {
            sk: pallas::Scalar::random(rng),
        }
    }

    /// Create from a raw scalar.
    pub fn from_scalar(sk: pallas::Scalar) -> Self {
        Self { sk }
    }

    /// Derive the spending key as a base field element (for use in Poseidon).
    pub fn to_base(&self) -> pallas::Base {
        // Map scalar field → base field via repr bytes
        let repr = self.sk.to_repr();
        let mut base_repr = [0u8; 32];
        base_repr.copy_from_slice(repr.as_ref());
        base_repr[31] &= 0x3f; // Ensure it's in the base field
        pallas::Base::from_repr(base_repr).unwrap_or(pallas::Base::from(0u64))
    }

    /// Get the raw scalar.
    pub fn scalar(&self) -> pallas::Scalar {
        self.sk
    }

    /// Derive the owner field element (public identity for note ownership).
    pub fn owner(&self) -> pallas::Base {
        poseidon_hash(self.to_base())
    }

    /// Derive the viewing key from this spending key.
    pub fn viewing_key(&self) -> ViewingKey {
        use group::Group;
        let vk = self.sk; // In production: vk = PRF(sk, "viewing")
        let pk = pallas::Point::generator() * vk;
        ViewingKey { vk, pk }
    }

    /// Derive the public key point (sk * G).
    pub fn public_key(&self) -> pallas::Point {
        use group::Group;
        pallas::Point::generator() * self.sk
    }
}

impl ViewingKey {
    pub fn scalar(&self) -> pallas::Scalar {
        self.vk
    }

    pub fn public_point(&self) -> pallas::Point {
        self.pk
    }
}

// Serde helpers for scalar/point types
mod scalar_serde {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(scalar: &pallas::Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(scalar.to_repr().as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<pallas::Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes);
        pallas::Scalar::from_repr(repr)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("invalid scalar"))
    }
}

mod point_serde {
    use group::GroupEncoding;
    use pasta_curves::pallas;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(point: &pallas::Point, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(point.to_bytes().as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<pallas::Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes);
        let opt = pallas::Point::from_bytes(&repr);
        if bool::from(opt.is_some()) {
            Ok(opt.unwrap())
        } else {
            Err(serde::de::Error::custom("invalid point"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spending_key_derives_consistent_owner() {
        let mut rng = rand::thread_rng();
        let sk = SpendingKey::random(&mut rng);
        let owner1 = sk.owner();
        let owner2 = sk.owner();
        assert_eq!(owner1, owner2);
    }

    #[test]
    fn different_keys_different_owners() {
        let mut rng = rand::thread_rng();
        let sk1 = SpendingKey::random(&mut rng);
        let sk2 = SpendingKey::random(&mut rng);
        assert_ne!(sk1.owner(), sk2.owner());
    }
}
