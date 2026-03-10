use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pasta_curves::pallas;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("ECDH key exchange failed")]
    EcdhFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed — wrong key or corrupted data")]
    DecryptFailed,
}

/// Encrypt note data using ECDH on Pallas + HKDF-SHA256 + ChaCha20-Poly1305.
///
/// - `recipient_pk`: recipient's public key point (vk * G)
/// - `ephemeral_sk`: sender's ephemeral secret scalar
/// - `plaintext`: note data to encrypt
///
/// Returns (ephemeral_pk, ciphertext) where ephemeral_pk is sent alongside.
pub fn encrypt_note(
    recipient_pk: pallas::Point,
    ephemeral_sk: pallas::Scalar,
    plaintext: &[u8],
) -> Result<(pallas::Point, Vec<u8>), EncryptionError> {
    use group::Group;

    // ECDH: shared_secret = ephemeral_sk * recipient_pk
    let shared_point = recipient_pk * ephemeral_sk;
    let ephemeral_pk = pallas::Point::generator() * ephemeral_sk;

    // Derive symmetric key via HKDF
    let shared_bytes = {
        use group::GroupEncoding;
        shared_point.to_bytes()
    };
    let hk = Hkdf::<Sha256>::new(None, shared_bytes.as_ref());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"PIL_NoteEncryption", &mut key_bytes)
        .map_err(|_| EncryptionError::EcdhFailed)?;

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::EncryptFailed)?;
    let nonce = Nonce::from([0u8; 12]); // Single-use ephemeral key → zero nonce is safe
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptFailed)?;

    Ok((ephemeral_pk, ciphertext))
}

/// Decrypt note data using the recipient's viewing key.
///
/// - `viewing_sk`: recipient's viewing secret scalar
/// - `ephemeral_pk`: sender's ephemeral public key (sent with ciphertext)
/// - `ciphertext`: encrypted note data
pub fn decrypt_note(
    viewing_sk: pallas::Scalar,
    ephemeral_pk: pallas::Point,
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // ECDH: shared_secret = viewing_sk * ephemeral_pk
    let shared_point = ephemeral_pk * viewing_sk;

    let shared_bytes = {
        use group::GroupEncoding;
        shared_point.to_bytes()
    };
    let hk = Hkdf::<Sha256>::new(None, shared_bytes.as_ref());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"PIL_NoteEncryption", &mut key_bytes)
        .map_err(|_| EncryptionError::EcdhFailed)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::DecryptFailed)?;
    let nonce = Nonce::from([0u8; 12]);
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::Group;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = rand::thread_rng();

        // Recipient keys
        let recipient_sk = pallas::Scalar::random(&mut rng);
        let recipient_pk = pallas::Point::generator() * recipient_sk;

        // Sender creates ephemeral key
        let ephemeral_sk = pallas::Scalar::random(&mut rng);

        let plaintext = b"Note: value=100, owner=0xDEAD";
        let (epk, ciphertext) = encrypt_note(recipient_pk, ephemeral_sk, plaintext).unwrap();

        let decrypted = decrypt_note(recipient_sk, epk, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let mut rng = rand::thread_rng();
        let recipient_sk = pallas::Scalar::random(&mut rng);
        let recipient_pk = pallas::Point::generator() * recipient_sk;
        let ephemeral_sk = pallas::Scalar::random(&mut rng);

        let (epk, ciphertext) = encrypt_note(recipient_pk, ephemeral_sk, b"secret").unwrap();

        // Wrong key
        let wrong_sk = pallas::Scalar::random(&mut rng);
        assert!(decrypt_note(wrong_sk, epk, &ciphertext).is_err());
    }
}
