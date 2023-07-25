use crate::{initiator::Initiator, responder::Responder, handshake::HandshakeOp};
use chacha20poly1305::ChaCha20Poly1305;
use secp256k1::{KeyPair, PublicKey, Secp256k1, XOnlyPublicKey};

#[test]
fn test_1() {
    let key_pair = Responder::<ChaCha20Poly1305>::generate_key();

    let mut initiator = Initiator::<ChaCha20Poly1305>::new(key_pair.public_key().into());
    let mut responder = Responder::<ChaCha20Poly1305>::new(key_pair);
    let first_message = initiator.step_0().unwrap();
    let second_message = responder.step_1(first_message).unwrap();
    let thirth_message = initiator.step_2(second_message).unwrap();
    let (fourth_message, mut codec_responder) = responder.step_3(thirth_message.to_vec()).unwrap();
    let mut codec_initiator = initiator.step_4(fourth_message).unwrap();
    let mut message = "ciao".as_bytes().to_vec();
    codec_initiator.encrypt(&mut message).unwrap();
    assert!(message != "ciao".as_bytes().to_vec());
    codec_responder.decrypt(&mut message).unwrap();

    assert!(message == "ciao".as_bytes().to_vec());
}
