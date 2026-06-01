use std::sync::Arc;
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{tungstenite::Message};
use whispr_core::{LibError, Message as WhisprMessage, cryptography::{ed25519::verify_data, hash}, models::ServerMessage};
use ed25519_dalek::{Signature, VerifyingKey};
use crate::{state::ServerState};
use base64::{Engine as _, engine::general_purpose};

pub async fn handle_connection(stream_raw: TcpStream, state: Arc<ServerState>) -> Result<(), LibError> {
    let stream_ws = tokio_tungstenite::accept_async(stream_raw).await.map_err(|e| LibError::WebSocketError(e.to_string()))?;
    let (mut sender, mut receiver) = stream_ws.split();
    
    let user_hash: [u8; 32] =
        if let Some(Ok(Message::Binary(message))) = receiver.next().await {
            match postcard::from_bytes::<ServerMessage>(&message).map_err(|e| LibError::DeserializationError(e.to_string()))? {
                ServerMessage::Identify(identify) => {
                    if verify_data(&identify.public_key, &Signature::from(identify.signature), &VerifyingKey::from_bytes(&identify.public_key).map_err(|e| LibError::KeyError(e.to_string()))?) {
                        hash(&identify.public_key)
                    }
                    else {
                        return Err(LibError::InvalidIdentity);
                    }
                },
                
                _ => return Err(LibError::InvalidIdentity)
            }
        }
        else {
            return Err(LibError::InvalidIdentity)
        };

    let (tx, mut rx) = mpsc::unbounded_channel();

    let mut map = state.clients.lock().await;
    map.insert(user_hash, tx);
    drop(map);

    println!("New client connected: {}", general_purpose::STANDARD.encode(user_hash));

    let output = loop {
        tokio::select! {
        msg = receiver.next() => {
            match msg {
                Some(Ok(payload)) => {
                    match payload {
                        Message::Binary(bytes) => {
                            match postcard::from_bytes(&bytes) {
                                Ok(ServerMessage::Message(envelope)) => {
                                    match postcard::from_bytes::<WhisprMessage>(&envelope.message) {
                                        Ok(message) => {
                                            let dest = message.reciever_hash;

                                            let map = state.clients.lock().await;
                                            if let Some(tx) = map.get(&dest) {
                                                let _ = tx.send(bytes.to_vec());
                                            }
                                            else {
                                                todo!()
                                            }
                                            drop(map);
                                        }

                                        Err(e) => {
                                            break Err(LibError::SerializationError(e.to_string()))
                                        }
                                    }
                                }
                                
                                Err(e) => break Err(LibError::SerializationError(e.to_string())),
                                
                                _ => break Err(LibError::UnknownError("binary frame was Ok but not a valid ServerMessage::Message".to_string()))
                            }
                        }
                        
                        Message::Close(_) => {
                            println!("Connection closed: {}", general_purpose::STANDARD.encode(user_hash));
                            break Ok(())
                        }
                        
                        _ => ()
                    }
                }
                
                Some(Err(e)) => break Err(LibError::WebSocketError(e.to_string())),

                None => break Ok(())
            }
        }
        
        
        msg = rx.recv() => { 
            if let Some(bytes) = msg {
                let frame = Message::Binary(tokio_tungstenite::tungstenite::Bytes::from(bytes));
                match sender.send(frame).await.map_err(|e| LibError::WebSocketError(e.to_string())) {
                    Ok(_) => (),
                    Err(e) => break Err(e)
                }
            }
            else {
                ()
            }
        } 
        }
    };
    let mut map = state.clients.lock().await;
    map.remove(&user_hash);
    drop(map);
    return output
}