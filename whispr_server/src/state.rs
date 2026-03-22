use tokio::sync::{Mutex, mpsc};
use std::collections::HashMap;

pub struct ServerState {
    clients: Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>
}

impl ServerState {
    pub fn new() -> Self {
        Self { clients: Mutex::new(HashMap::new()) }
    }
}
impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}