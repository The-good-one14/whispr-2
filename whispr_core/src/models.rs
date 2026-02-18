use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::Sha224;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub mod constants {
    pub const MESSAGE_LABEL: &[u8;23] = b"Whispr-message-label v1";
}

pub enum LibError {
    KeyLengthError(Option<String>),
    EncryptionError(Option<String>),
    DecryptionError(Option<String>),
    NonceError(Option<String>),
    SerializationError(Option<String>),
    NoSharedSecretError,
    RandomNumberError
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
    pub message: Message,
    #[serde(with = "serde_bytes")]
    pub signature: [u8;64]
}

pub struct Identity {
    pub private: SigningKey,
    pub public: VerifyingKey,
    pub fingerprint: [u8;32]
}

pub struct Session {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
    pub shared: Option<SharedSecret>
}