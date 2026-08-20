// All enums, structs, and constants

use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use thiserror::Error;

pub mod constants {
    pub const ENCRYPTION_LABEL: &[u8] = b"Whispr encryption label";
}

// To simplify errors, there is an enum for that including their respective error messages
#[derive(Error, Debug)]
pub enum LibError {
    #[error("Cryptographic key length was invalid: {0}")]
    KeyLengthError(String),
    #[error("Key-related error: {0}")]
    KeyError(String),
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
    #[error("Unknown error: {0}")]
    UnknownError(String)
}

// An enum for both signed and unsigned (unverified) messages
pub enum Verification {
    Signature(bool),
    NoSignature
}

// For all the types of messages a client-server connection needs
#[derive(serde::Serialize, serde::Deserialize)]
pub enum ServerMessage {
    // For identifying yourself to the server
    Identify(Identify),
    // For sending a message to someone over the server
    Message(Envelope),
    // For sending a message back to the client
    ClientMessage(ClientMessage)
}

// For all the Messages a server needs to send back to the client
#[derive(Error, Debug, serde::Serialize, serde::Deserialize)]
pub enum ClientMessage {
    #[error("Error sending message: {0}")]
    MessageFailed(String),
}

// A struct for identifying yourself to the server at the start of a connection
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Identify {
    pub public_key: [u8;32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8;64],
    
}

// To handle both types of x25519 keys
pub enum SecretKeyType {
    EphemeralSecret(EphemeralSecret),
    StaticSecret(StaticSecret)
}

// The struct of a message sent to another client
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub sender_hash: [u8;32],
    pub reciever_hash: [u8;32],
    pub public_key: [u8;32],
    pub nonce: [u8;12],
    pub payload: Vec<u8>
}

// The struct sent over the connection, with the Message (serialized) and signature
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub message: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: [u8;64]
}

// A struct for clients to store all the various keys
pub struct Identity {
    pub private: SigningKey,
    pub public: VerifyingKey,
    pub fingerprint: [u8;32],
    pub x25519_private: StaticSecret,
    pub x25519_public: PublicKey
}

// For ephemeral x25519 keypairs to be stored in 1 variable
pub struct Session {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}