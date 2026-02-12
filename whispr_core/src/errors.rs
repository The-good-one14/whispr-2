pub enum LibError {
    KeyLengthError(Option<String>),
    EncryptionError(Option<String>),
    DecryptionError(Option<String>),
    NonceError(Option<String>),
    RandomNumberError,
}