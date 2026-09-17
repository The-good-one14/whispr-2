use std::{collections::HashMap};
use tokio::sync::Mutex;
use whispr_core::{Message, models::Identity};
use ed25519_dalek::VerifyingKey;
use whispr_core::models::Verification;

#[derive(serde::Deserialize)]
pub enum GeneralMessage {
    Text(String),
    Image(Vec<u8>),
    Raw(Vec<u8>)

}
pub struct DisplayMessage {
    pub is_verified: Verification,
    pub payload: GeneralMessage
}
pub struct State {
    pub identity: Identity,
    pub history: Mutex<HashMap<[u8;32], Vec<DisplayMessage>>>,
    pub peers: Mutex<HashMap<[u8;32], VerifyingKey>>

}
pub struct OutboundMessage {
    pub reciever_hash: [u8;32],
    pub public_key: [u8;32],
    pub payload: Vec<u8>
}
pub enum InternalMessage {
    Send(OutboundMessage),
}