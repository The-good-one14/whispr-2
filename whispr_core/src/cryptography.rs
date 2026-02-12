use rand::{RngCore, rngs::OsRng};
use ed25519_dalek::{SigningKey, VerifyingKey, Verifier, Signature, Signer};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use crate::errors::LibError;
use chacha20_poly1305;

pub fn hash(data: &[u8]) -> [u8;32] {
    Sha256::digest(data).into()
}

pub fn derive_key(secret: &[u8], label: &[u8], salt: Option<&[u8]>) -> Result<[u8;32],LibError> {
    let kdf = Hkdf::<Sha256>::new(salt, secret);
    let mut output = [0u8;32];
    kdf.expand(label, &mut output).map_err(|_| LibError::KeyLengthError)?;
    Ok(output)
}

pub mod ed25519 {
    use super::*;

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
    use super::*;
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
    use super::*;

    fn nonce() -> [u8;12] {
        let mut nonce = [0u8;12];
        OsRng.try_fill_bytes(&mut nonce).unwrap();
        nonce
    }
    pub fn seal(data: &[u8], key: &[u8]) -> Vec<u8> {
        let nonce: [u8; 12] = nonce();
        Vec::new()
    }
}