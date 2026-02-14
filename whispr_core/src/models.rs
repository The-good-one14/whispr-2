pub enum LibError {
    KeyLengthError(Option<String>),
    EncryptionError(Option<String>),
    DecryptionError(Option<String>),
    NonceError(Option<String>),
    RandomNumberError,
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