use std::io::{self as stdio, Write};
use std::sync::Arc;

use base64::engine::general_purpose;
use base64::{Engine as _};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use whispr_core::LibError;

use crate::models::{GeneralMessage, InternalMessage, OutboundMessage, State};

fn ask_for_data(label: &str) -> Result<[u8;32], LibError> {
    
    print!("{}", label);
    stdio::stdout()
        .flush()
        .map_err(|e| LibError::UnknownError(e.to_string()))?;

    let mut input = String::new();
    stdio::stdin().read_line(&mut input)
        .map_err(|e| LibError::UnknownError(e.to_string()))?;
    let input = input.trim();

    let bytes = general_purpose::STANDARD.decode(input)
        .map_err(|e| LibError::DeserializationError(e.to_string()))?;
    let data: [u8;32] = bytes.try_into().map_err(|_| LibError::UnknownError("Input not correct length".to_string()))?;
    Ok(data)
}

pub async fn start_debug_chat(tx: mpsc::UnboundedSender<InternalMessage>, state: Arc<State>) -> Result<(), LibError> {
    let input = io::stdin();
    let mut reader = BufReader::new(input).lines();

    let fingerprint = ask_for_data("Enter the recipients fingerprint (base64): ")?;
    let ed25519_public_key_bytes = ask_for_data("Enter the recipients ed25519 public key (base64): ")?;
    let x25519_public_key = ask_for_data("Enter the recipients x25519 public key (base64): ")?;

    let ed25519_public_key = VerifyingKey::from_bytes(&ed25519_public_key_bytes)
        .map_err(|e| LibError::UnknownError(e.to_string()))?;

    state.peers.lock().await.insert(fingerprint.clone(), ed25519_public_key);

    loop {
        print!("> ");
        let _ = std::io::stdout().flush();

        match reader.next_line().await {
            Ok(Some(raw)) => {
                let text = raw.trim();
                if !text.is_empty() {
                    let payload = postcard::to_stdvec(&GeneralMessage::Text(text.to_string())).map_err(|e| LibError::SerializationError(e.to_string()))?;
                    let _ = tx.send(InternalMessage::Send(OutboundMessage { reciever_hash: fingerprint, public_key: x25519_public_key, payload }));
                }
            },
            Ok(None) => break Ok(()),

            Err(e) => return Err(LibError::UnknownError(e.to_string()))
            
        }
    }
}