pub enum connectionStatus {
    handshake,
    connected,
    unresponding,
    disconnecting,
    terminated,
}

pub struct connection {
    pub id: u32,
    pub uuid: String,
    pub publicKey: String,
    pub status: connectionStatus()
}
