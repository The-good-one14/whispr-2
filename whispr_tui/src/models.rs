use std::{collections::HashMap};
use tokio::sync::Mutex;
use whispr_core::models::Identity;
use ed25519_dalek::VerifyingKey;

#[derive(serde::Deserialize)]
pub enum GeneralMessage {
    Text(String),
    Image(Vec<u8>),
    Raw(Vec<u8>)

}
pub struct DisplayMessage {
    pub is_verified: verified,
    pub payload: GeneralMessage
}
pub struct State {
    pub identity: Identity,
    pub history: Mutex<HashMap<[u8;32], Vec<DisplayMessage>>>,
    pub peers: Mutex<HashMap<[u8;32], VerifyingKey>>

}