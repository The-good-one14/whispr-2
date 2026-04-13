use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use thiserror::Error;

pub mod constants {
    pub const ENCRYPTION_LABEL: &[u8] = b"Whispr-x25519-key-label v1";
}
#[derive(Error, Debug)]
pub enum LibError {
    #[error("Cryptographic key lenth was invalid: {0}")]
    KeyLengthError(String),
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Deserialization failed: {0}")]
    DeserializationError(String),
    #[error("Websocket failed: {0}")]
    WebSocketError(String),
    #[error("Client identity was invalid")]
    InvalidIdentity,
    #[error("Random number error")]
    RandomNumberError,
    #[error("Message had a bad signature")]
    BadSignature,
    #[error("Unknown error: {0}")]
    UnknownError(String)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum ServerMessage {
    Identify(Identify),
    Message(Envelope)
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Identify {
    pub hash: [u8;32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8;64],
    
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