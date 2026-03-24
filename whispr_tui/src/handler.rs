use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream, tungstenite::Message};
use whispr_core::LibError;
use tokio::net::TcpStream;

pub struct Connection {
    pub reciever: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    pub sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>
}

impl Connection {
    pub async fn connect(addr: String, port: String) -> Result<Self, LibError> {
        let connection = tokio_tungstenite::connect_async(format!("{}:{}", addr, port)).await.map_err(|e| LibError::WebSocketError(e.to_string()))?;
        
        todo!()
    }
}

pub async fn connection_handler(addr: String, port: String) -> Result<(), LibError> {
    loop {
        match Connection::connect(addr, port).await {
            Ok(e) => {
                todo!()
            }
            Err(e) => return Err(LibError::WebSocketError(e.to_string()))
        }
    }
}