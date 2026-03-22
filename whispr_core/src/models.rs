use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub mod constants {
    pub const ENCRYPTION_LABEL: [u8;26] = *b"Whispr-x25519-key-label v1";
}

pub enum LibError {
    KeyLengthError(Option<String>),
    EncryptionError(Option<String>),
    DecryptionError(Option<String>),
    NonceError(Option<String>),
    SerializationError(Option<String>),
    DeserializationError(Option<String>),
    RandomNumberError,
    BadSignature
}

pub enum SecretKeyType {
    EphemeralSecret(EphemeralSecret),
    StaticSecret(StaticSecret)
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub sender_hash: [u8;32],
    pub reciever_hash: [u8;32],
    pub public_key: [u8;32],
    pub nonce: [u8;12],
    pub payload: Vec<u8>
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub message: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: [u8;64]
}

pub struct Identity {
    pub private: SigningKey,
    pub public: VerifyingKey,
    pub fingerprint: [u8;32],
    pub x25519_private: StaticSecret,
    pub x25519_public: PublicKey
}

pub struct Session {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}