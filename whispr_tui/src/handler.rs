use std::{str::from_utf8, sync::Arc};

use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::{Bytes, Message}};
use whispr_core::{Envelope, LibError, cryptography::ed25519::sign_data, models::{Identify, Message as WhisprMessage, ServerMessage}, open_n_verify};
use tokio::net::TcpStream;

use crate::models::{DisplayMessage, GeneralMessage, State};

struct Connection {
    reciever: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>
}
impl Connection {
    async fn connect(addr: &String, port: &String) -> Result<Self, LibError> {
        let connection = tokio_tungstenite::connect_async(format!("ws://{}:{}", addr, port)).await.map_err(|e| LibError::WebSocketError(e.to_string()))?;
        let (sender, reciever) = connection.0.split();
        Ok(Connection {reciever, sender})
    }
    async fn disconnect(mut connection: Self) {
        _ = connection.sender.send(Message::Close(None));
        drop(connection);
    }
}



pub async fn connection_handler(state: Arc<State>, addr: String, port: String) -> Result<(), LibError> {
    loop {
        match Connection::connect(&addr, &port).await {
            Ok(mut connection) => {
                let identify: Identify = Identify { hash: state.identity.fingerprint, signature: sign_data(&state.identity.fingerprint, &state.identity.private).to_bytes()};
                let id: Vec<u8> = postcard::to_stdvec(&ServerMessage::Identify(identify))
                    .map_err(|e| LibError::SerializationError(e.to_string()))?;
                
                connection.sender.send(Message::Binary(Bytes::from(id)))
                    .await
                    .map_err(|e| LibError::WebSocketError(e.to_string()))?;
                loop {
                    tokio::select! {
                        msg = connection.reciever.next() => {
                            match msg {
                                Some(result) => {
                                    match result {
                                        Ok(message) => {
                                            match message {
                                                Message::Binary(bytes) => {
                                                    let envelope = postcard::from_bytes::<Envelope>(&bytes)
                                                        .map_err(|e| LibError::SerializationError(e.to_string()))?;
                                                    let sender = postcard::from_bytes::<WhisprMessage>(&envelope.message)
                                                        .map_err(|e| LibError::SerializationError(e.to_string()))?.sender_hash;
                                                    let peers = state.peers.lock().await;
                                                    let public_key = *peers.get(&sender);
                                                    drop(peers);
                                                    
                                                    let message = open_n_verify(envelope, &state.identity, public_key);
                                                    match message {
                                                        Ok((message, verified)) => {
                                                            let payload = postcard::from_bytes::<GeneralMessage>(&message)
                                                                .map_err(|e| LibError::DeserializationError(e.to_string()))?;
                                                            let displaymessage = DisplayMessage{payload, is_verified: verified};
                                                            let mut history = state.history.lock().await;
                                                            let entry = history.entry(sender).or_insert(Vec::new());
                                                            entry.push(displaymessage);
                                                            drop(history);
                                                        },
                                                        Err(e) => eprintln!("Error opening incoming message: {}", e)
                                                    }
                                                }
                                                _ => ()
                                            }
                                        }
                                        
                                        Err(e) => eprintln!("Error recieving WebSocket frame: {}", e)
                                    }
                                }
                                None => {
                                    break;
                                }
                            }
                        }

                        msg = todo() => {

                        }
                    }
                }
            }
            Err(e) => return Err(LibError::WebSocketError(e.to_string()))
        }
    }
}