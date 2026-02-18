use crate::{cryptography::{ed25519::{sign_data, get_public}, crypt::{generate_nonce, seal, open}, hash, derive_key}};
use crate::models::{Envelope, Identity, Message, Session, LibError, constants::{MESSAGE_LABEL}};
use chacha20poly1305::{Key, Nonce};
use ed25519_dalek::SigningKey;

pub fn get_identity(private: SigningKey) -> Identity {
    Identity {
        fingerprint: hash(private.as_bytes()),
        public: get_public(&private),
        private
    }
}

pub fn seal_n_sign(message: Message, identity: Identity, session: Session, nonce: [u8;12]) -> Result<Envelope, LibError> {
    if session.shared.is_none() {
        return Err(LibError::NoSharedSecretError);
    }
    let key = derive_key(session.shared.unwrap().as_bytes(), MESSAGE_LABEL, None)?;
    let message_bytes = postcard::to_stdvec(&message).map_err(|e| LibError::SerializationError(Some(e.to_string())))?;
    let message_bytes = seal(&message_bytes, &key, &nonce)?;
    let signature = sign_data(&message_bytes, &identity.private);
    
}