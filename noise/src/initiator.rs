use std::ptr;

use crate::aed_cipher::AeadCipher;
use crate::cipher_state::{Cipher, CipherState, GenericCipher};
use crate::error::Error;
use crate::handshake::HandshakeOp;
use crate::{signature_message::SignatureNoiseMessage, NoiseCodec};
use aes_gcm::KeyInit;
use chacha20poly1305::ChaCha20Poly1305;
use secp256k1::KeyPair;
use secp256k1::XOnlyPublicKey;

pub struct Initiator<C: AeadCipher> {
    handshake_cipher: Option<ChaCha20Poly1305>,
    k: Option<[u8; 32]>,
    n: u64,
    // Chaining key
    pub ck: [u8; 32],
    // Handshake hash
    h: [u8; 32],
    // ephemeral keypair
    e: KeyPair,
    // upstream pub key
    pk: XOnlyPublicKey,
    c1: Option<GenericCipher<C>>,
    c2: Option<GenericCipher<C>>,
}

/// Make sure that Initiator is not sync so we do not need to worry about what other memory accessor see
/// after that we zeroize k is send cause if we send it the original thread can not access
/// anymore it
impl<C: AeadCipher> !Sync for Initiator<C> {}
impl<C: AeadCipher> !Copy for Initiator<C> {}

impl<C: AeadCipher> CipherState<ChaCha20Poly1305> for Initiator<C> {
    fn get_k(&mut self) -> &mut Option<[u8; 32]> {
        &mut self.k
    }
    fn get_n(&self) -> u64 {
        self.n
    }
    fn set_n(&mut self, n: u64) {
        self.n = n;
    }
    fn get_cipher(&mut self) -> &mut Option<ChaCha20Poly1305> {
        &mut self.handshake_cipher
    }

    fn set_k(&mut self, k: Option<[u8; 32]>) {
        self.k = k;
    }
}

impl<C: AeadCipher> HandshakeOp<ChaCha20Poly1305> for Initiator<C> {
    fn name(&self) -> String {
        "Initiator".to_string()
    }
    fn get_h(&mut self) -> &mut [u8; 32] {
        &mut self.h
    }

    fn get_ck(&mut self) -> &mut [u8; 32] {
        &mut self.ck
    }

    fn set_h(&mut self, data: [u8; 32]) {
        self.h = data;
    }

    fn set_ck(&mut self, data: [u8; 32]) {
        self.ck = data;
    }

    fn set_handshake_cipher(&mut self, cipher: ChaCha20Poly1305) {
        self.handshake_cipher = Some(cipher);
    }
}

impl<C: AeadCipher> Initiator<C> {
    pub fn new(pk: XOnlyPublicKey) -> Box<Self> {
        let mut self_ = Self {
            handshake_cipher: None,
            k: None,
            n: 0,
            ck: [0; 32],
            h: [0; 32],
            e: Self::generate_key(),
            pk,
            c1: None,
            c2: None,
        };
        self_.initialize_self();
        Box::new(self_)
    }

    /// #### 4.5.1.1 Initiator
    ///
    /// Initiator generates ephemeral keypair and sends the public key to the responder:
    ///
    /// 1. initializes empty output buffer
    /// 2. generates ephemeral keypair `e`, appends `e.public_key` to the buffer (32 bytes plaintext public key)
    /// 3. calls `MixHash(e.public_key)`
    /// 4. calls `EncryptAndHash()` with empty payload and appends the ciphertext to the buffer (note that _k_ is empty at this point, so this effectively reduces down to `MixHash()` on empty data)
    /// 5. submits the buffer for sending to the responder in the following format
    ///
    /// ##### Ephemeral public key message:
    ///
    /// | Field name | Description                      |
    /// | ---------- | -------------------------------- |
    /// | PUBKEY     | Initiator's ephemeral public key |
    ///
    /// Message length: 32 bytes
    pub fn step_0(&mut self) -> Result<[u8; 32], aes_gcm::Error> {
        let serialized = self.e.public_key().x_only_public_key().0.serialize();
        self.mix_hash(&serialized);
        self.encrypt_and_hash(&mut vec![])?;

        let mut message = [0u8; 32];
        message[..32].copy_from_slice(&serialized[..32]);
        Ok(message)
    }

    /// #### 4.5.2.2 Initiator
    ///
    /// 1. receives NX-handshake part 2 message
    /// 2. interprets first 32 bytes as `re.public_key`
    /// 3. calls `MixHash(re.public_key)`
    /// 4. calls `MixKey(ECDH(e.private_key, re.public_key))`
    /// 5. decrypts next 48 bytes with `DecryptAndHash()` and stores the results as `rs.public_key` which is **server's static public key** (note that 32 bytes is the public key and 16 bytes is MAC)
    /// 6. calls `MixKey(ECDH(e.private_key, rs.public_key)`
    /// 7. decrypts next 90 bytes with `DecryptAndHash()` and deserialize plaintext into `SIGNATURE_NOISE_MESSAGE` (74 bytes data + 16 bytes MAC)
    /// 8. return pair of CipherState objects, the first for encrypting transport messages from initiator to responder, and the second for messages in the other direction:
    ///    1. sets `temp_k1, temp_k2 = HKDF(ck, zerolen, 2)`
    ///    2. creates two new CipherState objects `c1` and `c2`
    ///    3. calls `c1.InitializeKey(temp_k1)` and `c2.InitializeKey(temp_k2)`
    ///    4. returns the pair `(c1, c2)`
    ///
    ///
    ///
    /// ### 4.5.4 Cipher upgrade part 1: `-> AEAD_CIPHERS`
    ///
    /// Initiator provides list of AEAD ciphers other than ChaChaPoly that it supports
    ///
    /// | Field name | Description |
    /// | ---------- | ----------- |
    /// | SEQ0_32[u32] | List of AEAD cipher functions other than ChaChaPoly that the client supports |
    ///
    /// Message length: 1 + _n_ \* 4 bytes, where n is the length byte of the SEQ0_32 field, at most 129
    ///
    /// possible cipher codes:
    ///
    /// | cipher code | Cipher description |
    /// | ----------- | ------------------ |
    /// | 0x47534541 (b"AESG") | AES-256 with with GCM from [7] |
    ///
    pub fn step_2(&mut self, message: [u8; 170]) -> Result<[u8; 5], Error> {
        // 2. interprets first 32 bytes as `re.public_key`
        // 3. calls `MixHash(re.public_key)`
        let remote_pub_key = &message[0..32];
        self.mix_hash(remote_pub_key);

        // 4. calls `MixKey(ECDH(e.private_key, re.public_key))`
        let e_private_key = self.e.secret_bytes();
        self.mix_key(&Self::ecdh(&e_private_key[..], remote_pub_key)[..]);

        // 5. decrypts next 48 bytes with `DecryptAndHash()` and stores the results as `rs.public_key` which is **server's static public key** (note that 32 bytes is the public key and 16 bytes is MAC)
        let mut to_decrypt = message[32..80].to_vec();
        self.decrypt_and_hash(&mut to_decrypt)?;
        let rs_pub_key = to_decrypt;

        // 6. calls `MixKey(ECDH(e.private_key, rs.public_key)`
        self.mix_key(&Self::ecdh(&e_private_key[..], &rs_pub_key[..])[..]);

        let mut to_decrypt = message[80..170].to_vec();
        self.decrypt_and_hash(&mut to_decrypt)?;
        let plaintext: [u8; 74] = to_decrypt.try_into().unwrap();
        let signature_message: SignatureNoiseMessage = plaintext.into();

        // TODO 23.09.07 - There was a bug where we weren't using the received x_only pub key
        // to verify the signature.
        let rs_pk_xonly = XOnlyPublicKey::from_slice(&rs_pub_key).unwrap();
        if signature_message.verify(&rs_pk_xonly) {
            let (temp_k1, temp_k2) = Self::hkdf_2(self.get_ck(), &[]);
            let c1 = ChaCha20Poly1305::new(&temp_k1.into());
            let c2 = ChaCha20Poly1305::new(&temp_k2.into());
            let c1: Cipher<ChaCha20Poly1305> = Cipher::from_key_and_cipher(temp_k1, c1);
            let c2: Cipher<ChaCha20Poly1305> = Cipher::from_key_and_cipher(temp_k2, c2);
            self.c1 = Some(GenericCipher::ChaCha20Poly1305(c1));
            self.c2 = Some(GenericCipher::ChaCha20Poly1305(c2));
            // len = 1
            // 47,53,45,41 = AESG
            let supported_ciphers = [1, 0x47, 0x53, 0x45, 0x41];
            Ok(supported_ciphers)
        } else {
            Err(Error::InvalidCertificate(plaintext))
        }
    }

    /// #### 4.5.5.1 Upgrade to a new AEAD-cipher
    ///
    /// If the server provides a non-empty `CIPHER_CHOICE`:
    ///
    /// 1. Both initiator and responder create a new pair of CipherState objects with the negotiated cipher for encrypting transport messages from initiator to responder and in the other direction respectively
    /// 2. New keys `key_new` are derived from the original CipherState keys `key_orig` by taking the first 32 bytes from `ENCRYPT(key_orig, maxnonce, zero_len, zeros)` using the negotiated cipher function where `maxnonce` is 2<sup>64</sup> - 1, `zerolen` is a zero-length byte sequence, and `zeros` is a sequence of 32 bytes filled with zeros. (see `Rekey(k)` function<sup>[8](#reference-8)</sup>)
    /// 3. New CipherState objects are reinitialized: `InitializeKey(key_new)`.
    pub fn step_4(mut self, cipher_chosed: Vec<u8>) -> Result<NoiseCodec<C>, Error> {
        match cipher_chosed.len() {
            0 => Err(Error::InvalidCipherList(cipher_chosed)),
            1 => {
                if cipher_chosed[0] == 0 {
                    let mut encryptor = None;
                    std::mem::swap(&mut encryptor, &mut self.c1);
                    let mut decryptor = None;
                    std::mem::swap(&mut decryptor, &mut self.c2);
                    let mut encryptor = encryptor.unwrap();
                    let mut decryptor = decryptor.unwrap();
                    encryptor.erase_k();
                    decryptor.erase_k();
                    // Responder want to use ChaCha
                    let codec = crate::NoiseCodec {
                        encryptor,
                        decryptor,
                    };
                    Ok(codec)
                } else {
                    Err(Error::InvalidCipherList(cipher_chosed))
                }
            }
            5 => {
                // Responder want to use AesGcm
                if cipher_chosed == [1, 0x47, 0x53, 0x45, 0x41] {
                    let mut encryptor = None;
                    std::mem::swap(&mut encryptor, &mut self.c1);
                    let mut decryptor = None;
                    std::mem::swap(&mut decryptor, &mut self.c2);
                    let encryptor = encryptor.unwrap().into_aesg();
                    let decryptor = decryptor.unwrap().into_aesg();
                    let codec = crate::NoiseCodec {
                        encryptor,
                        decryptor,
                    };
                    Ok(codec)
                } else {
                    Err(Error::InvalidCipherList(cipher_chosed))
                }
            }
            _ => Err(Error::InvalidCipherList(cipher_chosed)),
        }
    }

    fn erase(&mut self) {
        if let Some(k) = self.k.as_mut() {
            for b in k {
                unsafe { ptr::write_volatile(b, 0) };
            }
        }
        for mut b in self.ck {
            unsafe { ptr::write_volatile(&mut b, 0) };
        }
        for mut b in self.h {
            unsafe { ptr::write_volatile(&mut b, 0) };
        }
        if let Some(c1) = self.c1.as_mut() {
            c1.erase_k()
        }
        if let Some(c2) = self.c2.as_mut() {
            c2.erase_k()
        }
        self.e.non_secure_erase();
    }
}
impl<C: AeadCipher> Drop for Initiator<C> {
    fn drop(&mut self) {
        self.erase();
    }
}
