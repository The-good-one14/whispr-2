use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use crate::models::LibError;


pub fn hash(data: &[u8]) -> [u8;32] {
    Sha256::digest(data).into()
}

pub fn derive_key(secret: &[u8], label: &[u8], salt: Option<&[u8]>) -> Result<[u8;32],LibError> {
    let kdf = Hkdf::<Sha256>::new(salt, secret);
    let mut output = [0u8;32];
    kdf.expand(label, &mut output).map_err(|e| LibError::KeyLengthError(Some(e.to_string())))?;
    Ok(output)
}

pub mod ed25519 {
    use ed25519_dalek::{SigningKey, VerifyingKey, Verifier, Signature, Signer};
    use rand::rngs::OsRng;

    pub fn generate() -> (SigningKey, VerifyingKey) {
        let mut random = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut random);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Signature {
        signing_key.sign(data)
    }

    pub fn verify_data(data: &[u8] , signature: &Signature, verifying_key: &VerifyingKey) -> bool {
        verifying_key.verify(data, &signature).is_ok()
    }
}

pub mod x25519 {
    use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
    use rand::rngs::OsRng;

    pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
        let random = OsRng;
        let secret = EphemeralSecret::random_from_rng(random);
        let public = PublicKey::from(&secret);
        (secret, public)
    }
    pub fn generate_shared(secret: EphemeralSecret, public: &PublicKey) -> SharedSecret {
        secret.diffie_hellman(&public)
    }
}

pub mod crypt {
    use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key, KeyInit, Nonce, aead::Aead};
    use rand::{RngCore, rngs::OsRng};
    use crate::models::LibError;

    pub fn generate_nonce() -> Result<[u8;12], LibError> {
        let mut nonce = [0u8;12];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| LibError::RandomNumberError)?;
        Ok(nonce)
    }
    pub fn seal(data: &[u8], kdf_key: &[u8;32], nonce: &[u8;12]) -> Result<Vec<u8>, LibError> {

        let nonce = Nonce::from_slice(nonce);
        ChaCha20Poly1305::new(Key::from_slice(kdf_key)).encrypt(nonce, data).map_err(|e| LibError::NonceError(Some(e.to_string())))
    }
    pub fn open(data: &[u8], kdf_key: &[u8;32], nonce: &[u8;12]) -> Result<Vec<u8>, LibError> {

        let nonce = Nonce::from_slice(nonce);
        ChaCha20Poly1305::new(Key::from_slice(kdf_key)).decrypt(nonce, data).map_err(|e| LibError::DecryptionError(Some(e.to_string())))
    }
}