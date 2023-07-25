//! Implement Sv2 noise https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md#4-protocol-security

#![feature(negative_impls)]

use aed_cipher::AeadCipher;
use aes_gcm::aead::Buffer;
use cipher_state::GenericCipher;
mod aed_cipher;
mod cipher_state;
mod error;
mod handshake;
mod initiator;
mod responder;
mod signature_message;
#[cfg(test)]
mod test;

const PARITY: secp256k1::Parity = secp256k1::Parity::Even;

/// protocolName is official noise protocol name such as Noise_NX_secp256k1_ChaChaPoly_SHA256 encoded as an ASCII string
pub const PROTOCOL_NAME_CHACHA: &str = "Noise_NX_secp256k1_ChaChaPoly_SHA256";
/// protocolName is official noise protocol name such as Noise_NX_secp256k1_AES-GCM_SHA256 encoded as an ASCII string
pub const PROTOCOL_NAME_AES: &str = "Noise_NX_secp256k1_AES-GCM_SHA256";
/// An encrypted message is tag_size bytes bigger than the clear message
pub const CHACHA_POLY_TAG_SIZE: usize = 16;
/// An encrypted message is tag_size bytes bigger than the clear message
pub const AES_GMC_TAG_SIZE: usize = 16;

/// If protocolName is less than or equal to 32 bytes in length, use protocolName with zero bytes
/// appended to make 32 bytes. Otherwise, apply HASH to it. For name =
/// "Noise_NX_secp256k1_ChaChaPoly_SHA256", we need the hash.
pub const HASHED_PROTOCOL_NAME_CHACHA: [u8; 32] = [
    168, 246, 65, 106, 218, 197, 235, 205, 62, 183, 118, 131, 234, 247, 6, 174, 180, 164, 162, 125,
    30, 121, 156, 182, 95, 117, 218, 138, 122, 135, 4, 65,
];

/// If protocolName is less than or equal to 32 bytes in length, use protocolName with zero bytes
/// appended to make 32 bytes. Otherwise, apply HASH to it. For name =
/// "Noise_NX_secp256k1_AES", we need the hash.
pub const HASHED_PROTOCOL_NAME_AES: [u8; 32] = [
    98, 20, 128, 113, 111, 137, 141, 202, 194, 70, 69, 231, 226, 122, 220, 145, 249, 218, 130, 51,
    53, 203, 242, 0, 71, 117, 5, 73, 173, 157, 32, 55,
];

pub struct NoiseCodec<C: AeadCipher> {
    encryptor: GenericCipher<C>,
    decryptor: GenericCipher<C>,
}

impl<C: AeadCipher> NoiseCodec<C> {
    pub fn encrypt<T: Buffer>(&mut self, msg: &mut T) -> Result<(), aes_gcm::Error> {
        self.encryptor.encrypt(msg)
    }
    pub fn decrypt<T: Buffer>(&mut self, msg: &mut T) -> Result<(), aes_gcm::Error> {
        self.decryptor.decrypt(msg)
    }
}

pub use initiator::Initiator;
pub use responder::Responder;
