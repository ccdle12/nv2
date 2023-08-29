use crate::{handshake::HandshakeOp, initiator::Initiator, responder::Responder};
use chacha20poly1305::ChaCha20Poly1305;

#[test]
fn test_1() {
    let key_pair = Responder::<ChaCha20Poly1305>::generate_key();

    let mut initiator = Initiator::<ChaCha20Poly1305>::new(key_pair.public_key().into());
    let mut responder = Responder::<ChaCha20Poly1305>::new(key_pair);

    let first_message = initiator.step_0().unwrap();
    let second_message = responder.step_1(first_message, 31449600).unwrap();
    let thirth_message = initiator.step_2(second_message).unwrap();

    // TODO: TMP, hardcoding default noise algorithms for testing purposes
    // let (fourth_message, mut codec_responder) = responder.step_3(thirth_message.to_vec()).unwrap();
    let (fourth_message, mut codec_responder) = responder.step_3(vec![0x00]).unwrap();
    // let mut codec_initiator = initiator.step_4(fourth_message).unwrap();
    let mut codec_initiator = initiator.step_4(vec![0x00]).unwrap();

    let mut message = "ciao".as_bytes().to_vec();
    codec_initiator.encrypt(&mut message).unwrap();
    println!("Mesage after encrypting: {:?}", &message);
    assert!(message != "ciao".as_bytes().to_vec());

    codec_responder.decrypt(&mut message).unwrap();
    assert!(message == "ciao".as_bytes().to_vec());
    println!("Mesage after decrypting: {:?}", &message);

    codec_responder.encrypt(&mut message).unwrap();
    assert!(message != "ciao".as_bytes().to_vec());
    println!("Mesage after decrypting: {:?}", &message);

    codec_initiator.decrypt(&mut message).unwrap();
    println!("Mesage after encrypting: {:?}", &message);
    assert!(message == "ciao".as_bytes().to_vec());

}
