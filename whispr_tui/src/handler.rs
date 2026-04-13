use std::{sync::Arc};

use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::{Bytes, Message}};
use whispr_core::{Envelope, LibError, models::{Message as WhisprMessage, ServerMessage}, open_n_verify};
use tokio::net::TcpStream;

use crate::models::State;

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
                let id: Vec<u8> = postcard::to_stdvec(&ServerMessage::Identify(state.identity.fingerprint)).map_err(|e| LibError::SerializationError(e.to_string()))?;
                _ = connection.sender.send(Message::Binary(Bytes::from(id))).await.map_err(|e| LibError::WebSocketError(e.to_string()))?;
                loop {
                    tokio::select! {
                        msg = connection.reciever.next() => {
                            match msg {
                                Some(result) => {
                                    match result {
                                        Ok(message) => {
                                            match message {
                                                Message::Binary(bytes) => {
                                                    let envelope = postcard::from_bytes::<Envelope>(&bytes.to_vec())
                                                    .map_err(|e| LibError::SerializationError(e.to_string()))?;
                                                    let sender = postcard::from_bytes::<WhisprMessage>(&envelope.message)
                                                    .map_err(|e| LibError::SerializationError(e.to_string()))?.sender_hash;
                                                    let peers = state.peers.lock().await;
                                                    let public_key = match peers.get(&sender) {
                                                        Some(key) => Some(*key),
                                                        None => None
                                                    };
                                                    drop(peers);
                                                    match public_key {
                                                        Some(key) => {
                                                            let message = open_n_verify(envelope, &state.identity, &key);
                                                            match message {
                                                                Ok((message, verified)) => (message, verified),
                                                                Err(e) => 
                                                            }

                                                        }
                                                        None => () // can't open without public key
                                                    }
                                                }
                                                _ => ()
                                            }
                                        }
                                        
                                        Err(e) => eprintln!("Error recieving WebSocket frame: {}", e.to_string())
                                    }
                                }
                                None => {
                                    break;
                                }
                            }
                        }

                        msg = todo() => {}
                    }
                }
            }
            Err(e) => return Err(LibError::WebSocketError(e.to_string()))
        }
    }
}