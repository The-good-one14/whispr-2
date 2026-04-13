use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;
use whispr_core::{cryptography::ed25519::get_private_from_seed, get_identity};

use crate::{models::State};

mod models;
mod handler;

const PRIVATE_KEY: [u8; 32] = [
    0x0d, 0xcc, 0xf1, 0x2f, 0x70, 0xff, 0xe1, 0xd5, 
    0x16, 0x21, 0x87, 0xa6, 0x00, 0xd0, 0x0a, 0x58, 
    0xe2, 0xee, 0x5f, 0x4b, 0xb8, 0x5a, 0x19, 0x94, 
    0x31, 0xca, 0xae, 0x37, 0x12, 0x1d, 0x23, 0xbe,
];

#[tokio::main]
async fn main() {
    let identity = get_identity(get_private_from_seed(PRIVATE_KEY)).expect("error getting identity");
    let state: Arc<models::State> = Arc::new(State{ identity, history: Mutex::new(HashMap::new()), peers: Mutex::new(HashMap::new())});
    let pointer = Arc::clone(&state);
    tokio::spawn(
        async move {
            handler::connection_handler(pointer, "127.0.0.1".to_string(), "8080".to_string())
        }
    );

}
