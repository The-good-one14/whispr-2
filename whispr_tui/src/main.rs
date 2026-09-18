use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::{Mutex, mpsc};
use whispr_core::{LibError, cryptography::ed25519::generate_new_pair, models::Verification::Signature, protocols::get_identity};

use crate::models::{DisplayMessage, GeneralMessage::{self, Text}, InternalMessage, OutboundMessage, State};

mod models;
mod handler;

#[tokio::main]
async fn main() {

    let identity = get_identity(generate_new_pair().0).expect("error getting identity");
    if cfg!(debug_assertions) {
        println!("fingerprint: {:?}", &identity.fingerprint.to_vec());
        println!("ed25519 public: {:?}", &identity.public.as_bytes());
        println!("x25519 public: {:?}", &identity.x25519_public.as_bytes());
    }
    let state: Arc<models::State> = Arc::new(State{ identity: identity, history: Mutex::new(HashMap::new()), peers: Mutex::new(HashMap::new())});
    let pointer = Arc::clone(&state);
    let (connection_tx, connection_rx) = mpsc::unbounded_channel::<InternalMessage>();

    let handle = tokio::spawn(
        async move {
            let _ = handler::connection_handler(pointer, "127.0.0.1".to_string(), "8080".to_string(), connection_rx).await;
        }
    );

    if cfg!(debug_assertions) {
        state.peers.lock().await.insert(state.identity.fingerprint.clone(), state.identity.public.clone());

        println!("Sending message...");
        _ = connection_tx.send(InternalMessage::Send(OutboundMessage {
            reciever_hash: state.identity.fingerprint.clone(),
            public_key: state.identity.x25519_public.to_bytes(),
            payload: postcard::to_stdvec(&GeneralMessage::Text("Hello, world!".to_string())).map_err(|e| LibError::SerializationError(e.to_string())).unwrap()
        }));
        let _ = tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*state.history.lock().await.get(&state.identity.fingerprint).unwrap().last().unwrap(), DisplayMessage { is_verified: Signature(true), payload: Text("Hello, world!".to_string()) })
    }

    tokio::signal::ctrl_c().await.unwrap();
    println!("Disconnecting...");
    let _ = connection_tx.send(InternalMessage::Disconnect);
    let _ = handle.await;
    println!("Disconnected.");
}
