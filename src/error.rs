use aes_gcm::Error as AesGcmError;

#[derive(Debug)]
pub enum Error {
    HandshakeNotFinalized,
    CipherListMustBeNonEmpty,
    UnsupportedCiphers(Vec<u8>),
    InvalidCipherList(Vec<u8>),
    InvalidCipherChosed(Vec<u8>),
    AesGcmError(AesGcmError),
    InvalidCipherState,
    InvalidCertificate([u8; 74]),
}

impl From<AesGcmError> for Error {
    fn from(value: AesGcmError) -> Self {
        Self::AesGcmError(value)
    }
}
