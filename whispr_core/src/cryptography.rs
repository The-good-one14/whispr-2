use rand::rngs::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey, Verifier, Signature};

pub fn create_keypair() -> (signing_key, verifying_key) {
    let mut random = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut random);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Signature {
    let signature: Signature = signing_key.sign(message);
}

pub fn verify_data(data: &[u8] , signature: &Signature, verifying_key: &VerifyingKey) -> bool {
    verifying_key.verify(data, &signature).is_ok()
}