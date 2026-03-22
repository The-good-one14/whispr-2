use std::sync::Arc;
use tokio::{io::unix::AsyncFd, net::TcpListener};

mod models;
mod state;
mod handler;

#[tokio::main]
async fn main() {

    let state: Arc<state::ServerState> = Arc::new(state::ServerState::new());

    let listener = TcpListener::bind(format!("{}:{}", models::IP_ADDR, models::IP_PORT))
    .await
    .expect(&format!("TCP Listener failed to open on {}:{}", models::IP_ADDR, models::IP_PORT));

    println!("Whispr Server is listening on {}...", models::IP_PORT);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let pointer = Arc::clone(&state);
                tokio::spawn(async move {
                    let res = handle_connection(stream, pointer).await;
                    if let Err(e) = res {
                        println!("Connection closed with error: {}", e);
                    }
                });
            }
            Err(e) => {
                print!("An error occured accepting tcp connection: {}", e)
            }
        }
    }
}