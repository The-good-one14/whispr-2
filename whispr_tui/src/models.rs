use std::{collections::HashMap};
use tokio::sync::Mutex;
use whispr_core::models::Identity;
use ed25519_dalek::VerifyingKey;

pub enum GeneralMessage {
    Text(String),
    Image(Vec<u8>),
    Raw(Vec<u8>)

}
pub struct DisplayMessage {
    pub is_verified: bool,
    pub payload: GeneralMessage
}

pub struct State {
    pub identity: Identity,
    pub history: Mutex<HashMap<[u8;32], Vec<DisplayMessage>>>,
    pub peers: Mutex<HashMap<[u8;32], VerifyingKey>>

}