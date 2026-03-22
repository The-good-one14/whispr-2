use std::sync::Arc;

use tokio::net::TcpStream;
use whispr_core::LibError;

use crate::state::ServerState;

pub async fn handle_connection(stream_raw: TcpStream, state: Arc<ServerState>) -> Result<(), LibError> {
    let mut stream_ws = tokio_tungstenite::accept_async(stream_raw).await.map_err(|e| LibError::WebSocketError(Some(e.to_string())));
    let mut user_hash = identify_ws(&mut stream_ws).await?;
    
    Ok(())
}