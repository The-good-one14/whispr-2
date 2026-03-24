use std::collections::HashMap;
use whispr_core::models::Identity;

pub struct DisplayMessage {
    is_verified: bool,
    text: str
}

pub struct State {
    pub identity: Identity,
    pub history: HashMap<[u8;32], Vec<DisplayMessage>>

}