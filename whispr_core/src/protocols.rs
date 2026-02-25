use crate::{cryptography::{crypt::{generate_nonce, open, seal}, derive_key, ed25519::{get_public, sign_data, verify_data}, hash, x25519::{generate_ephemeral, generate_shared, generate_static}}};
use crate::models::{Envelope, Identity, Message, Session, LibError, SecretKeyType, constants::ENCRYPTION_LABEL};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn get_identity(private: SigningKey) -> Result<Identity, LibError> {
    let static_keys: (StaticSecret, PublicKey) = generate_static(derive_key(private.as_bytes(), &ENCRYPTION_LABEL, None)?);
    Ok(Identity {
        fingerprint: hash(private.as_bytes()),
        public: get_public(&private),
        x25519_private: static_keys.0,
        x25519_public: static_keys.1,
        private
    })
}

pub fn seal_n_sign(message: &[u8], reciever: [u8;32], identity: Identity, publickey: &PublicKey) -> Result<Envelope, LibError> {
    let session: Session = generate_ephemeral();
    let shared = generate_shared(crate::models::SecretKeyType::EphemeralSecret(session.secret), publickey);
    let key: [u8;32] = derive_key(shared.as_bytes(), &ENCRYPTION_LABEL, None)?;
    let nonce = generate_nonce()?;
    let sealed_payload = seal(&message, &key, &nonce)?;
    let sealed_message: Message = Message {
        sender_hash: identity.fingerprint,
        reciever_hash: reciever,
        public_key: session.public.to_bytes(),
        nonce,
        payload: sealed_payload
    };
    let sealed_message_bytes: Vec<u8> = postcard::to_stdvec(&sealed_message).map_err(|e| LibError::SerializationError(Some(e.to_string())))?;
    let signature: [u8; 64] = sign_data(&sealed_message_bytes, &identity.private).to_bytes();
    Ok(Envelope {
        message: sealed_message_bytes,
        signature
    })
}

pub fn open_n_verify(envelope: Envelope, identity: &Identity, public_key: &VerifyingKey) -> Result<Vec<u8>, LibError> {
    if !verify_data(&envelope.message, &Signature::from_bytes(&envelope.signature), &public_key) {
        return Err(LibError::BadSignature);
    }
    let message: Message = postcard::from_bytes(&envelope.message).map_err(|e| LibError::DecryptionError(Some(e.to_string())))?;
    let key: [u8; 32] = derive_key(generate_shared(SecretKeyType::StaticSecret(identity.x25519_private.clone()), &PublicKey::from(message.public_key)).as_bytes(), &ENCRYPTION_LABEL, None)?;
    Ok(open(&message.payload, &key, &message.nonce)?)

}