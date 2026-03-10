use pasta_curves::pallas;

/// Base field element (Pallas base field).
pub type Base = pallas::Base;

/// Scalar field element (Pallas scalar field).
pub type Scalar = pallas::Scalar;

/// A note commitment — a Poseidon hash of note contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Commitment(#[serde(with = "field_serde")] pub Base);

/// A nullifier — a domain-separated hash that marks a note as spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Nullifier(#[serde(with = "field_serde")] pub Base);

impl Nullifier {
    /// Constant-time equality check (prevents timing side-channels).
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        use ff::PrimeField;
        use subtle::ConstantTimeEq;
        self.0.to_repr().ct_eq(&other.0.to_repr())
    }
}

/// Serde helper for Pallas field elements (hex encoding).
mod field_serde {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(field: &pallas::Base, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = field.to_repr();
        serializer.serialize_str(&hex::encode(bytes.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<pallas::Base, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut repr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        repr.copy_from_slice(&bytes);
        let opt = pallas::Base::from_repr(repr);
        if bool::from(opt.is_some()) {
            Ok(opt.unwrap())
        } else {
            Err(serde::de::Error::custom("invalid field element"))
        }
    }
}
