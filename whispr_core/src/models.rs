pub struct Message {
    pub sender_hash: [u8;32],
    pub reciever_hash: [u8;32],
    pub public_key: [u8;32],
    pub nonce: [u8;12],
    pub payload: Vec<u8>,
    pub signature: [u8;64]
}