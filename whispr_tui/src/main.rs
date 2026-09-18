use std::{collections::HashMap, sync::{Arc}};

use ed25519_dalek::SigningKey;
use tokio::sync::{Mutex, mpsc};
use whispr_core::{LibError, cryptography::{ed25519::{get_key_from_seed, get_public}, hash}, get_identity};

use crate::models::{InternalMessage::{self, Send}, OutboundMessage, State};

mod models;
mod handler;

const PRIVATE_KEY: [u8; 32] = [
    0x0d, 0xcc, 0xf1, 0x2f, 0x70, 0xff, 0xe1, 0xd5, 
    0x16, 0x21, 0x87, 0xa6, 0x00, 0xd0, 0x0a, 0x58, 
    0xe2, 0xee, 0x5f, 0x4b, 0xb8, 0x5a, 0x19, 0x94, 
    0x31, 0xca, 0xae, 0x37, 0x12, 0x1d, 0x23, 0xbe,
];
const PRIVATE_KEY_2: [u8; 32] = [
    0x0e, 0xcc, 0xf1, 0x2f, 0x70, 0xff, 0xe1, 0xd5, 
    0x16, 0x21, 0x87, 0xa6, 0x00, 0xd0, 0x0a, 0x58, 
    0xe2, 0xee, 0x5f, 0x4b, 0xb8, 0x5a, 0x19, 0x94, 
    0x31, 0xca, 0xae, 0x37, 0x12, 0x1d, 0x23, 0xbe,
];

#[tokio::main]
async fn main() {

    let identity = get_identity(get_key_from_seed(PRIVATE_KEY_2)).expect("error getting identity");
    let state: Arc<models::State> = Arc::new(State{ identity, history: Mutex::new(HashMap::new()), peers: Mutex::new(HashMap::new())});
    let pointer = Arc::clone(&state);
    let (connection_tx, mut connection_rx) = mpsc::unbounded_channel::<InternalMessage>();

    tokio::spawn(
        async move {
            let _ = handler::connection_handler(pointer, "127.0.0.1".to_string(), "8080".to_string(), connection_rx).await;
        }
    );
    
    print!("Press enter...");
    
    println!("Sending message...");
    _ = connection_tx.send(InternalMessage::Send(OutboundMessage {
        reciever_hash: hash(get_public(&SigningKey::from_bytes(&PRIVATE_KEY_2)).as_bytes()),
        public_key: get_public(&SigningKey::from_bytes(&PRIVATE_KEY_2)).to_bytes(),
        payload: postcard::to_stdvec("Hello, world!").map_err(|e| LibError::SerializationError(e.to_string())).unwrap()
    }));

    tokio::signal::ctrl_c().await.unwrap();
}
