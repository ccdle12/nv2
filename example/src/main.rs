use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use noise::{ChaCha20Poly1305, Responder, HandshakeOp, Initiator};

fn main() {
    run_responder();
    // run_initiator();
}

fn run_initiator() {
    let mut conn = TcpStream::connect("127.0.0.1:8080").unwrap();
    let key_pair = Initiator::<ChaCha20Poly1305>::generate_key();
    let mut initiator = Initiator::<ChaCha20Poly1305>::new(key_pair.public_key().into());
    let mut buf = [0; 1024];

    let first_msg = initiator.step_0().unwrap();
    buf[0..32].clone_from_slice(&first_msg);

    println!("DEBUG: Sending buffer: {:?}", &buf);
    conn.write(&buf).unwrap();

    // Feed to step 2?
    let mut buf_1 = [0; 1024];
    conn.read(&mut buf_1).unwrap();
    println!("DEBUG: Received ES: {:?}", &buf_1);
    let mut input = [0u8; 170];
    input.copy_from_slice(&buf_1[0..170]);

    // TODO: Not sending back this support algo message.
    let _ = initiator.step_2(input).unwrap();
    let mut codec_initiator = initiator.step_4(vec![0x00]).unwrap();

    // let mut message = "ciao".as_bytes().to_vec();
    let first_tx_msg = String::from("FOO");
    let bytes = first_tx_msg.as_bytes();
    let mut buff_2 = [0; 1024 - 16];
    buff_2[..bytes.len()].copy_from_slice(bytes);
    let mut buffer_2_final = buff_2.to_vec();
    println!("DEBUG: before encryption of transport state message 2: {:?}", &buffer_2_final);
    codec_initiator.encrypt(&mut buffer_2_final).unwrap();
    println!("DEBUG after encryption of transport state message 2: {:?}", &buffer_2_final);
    conn.write_all(&buffer_2_final).unwrap();

    let mut buf_3 = [0; 1024];
    conn.read(&mut buf_3).unwrap();
    let mut buf_3_owned = buf_3.to_vec();
    println!("DEBUG: Received transport state message, encrypted: {:?}", &buf_3_owned);
    codec_initiator.decrypt(&mut buf_3_owned).unwrap();
    println!("DEBUG: Received transport state message, decrypted: {:?}", &buf_3_owned);
}

fn run_responder() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    let mut buffer = [0; 1024];
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let bytes_read = stream.read(&mut buffer).unwrap();
                let received = &buffer[..bytes_read];

                let key_pair = Responder::<ChaCha20Poly1305>::generate_key();
                let mut responder = Responder::<ChaCha20Poly1305>::new(key_pair);

                let mut first_msg = [0u8; 32];
                first_msg.copy_from_slice(&buffer[..32]);
                let first_response = responder.step_1(first_msg, 31449600).unwrap();

                let res = stream.write_all(&first_response);
                assert!(res.is_ok());

                let supported_ciphers = vec![0x00];
                let (_,  mut codec_responder) = responder.step_3(supported_ciphers).unwrap();

                let bytes_read = stream.read(&mut buffer).unwrap();
                let mut received = buffer[..].to_owned();

                let first_tx_msg = codec_responder.decrypt(&mut received).unwrap();
                println!("DEBUG received decrypted transport state message 1: {:?}", &received);

                let first_response = String::from("FOO");
                let bytes = first_response.as_bytes();
                let mut buffer_2 = [0; 1024 - 16];
                buffer_2[..bytes.len()].copy_from_slice(bytes);
                let mut buffer_2_final = buffer_2.to_vec();
                println!("DEBUG: before encryption of transport state message 2: {:?}", &buffer_2_final);

                codec_responder.encrypt(&mut buffer_2_final).unwrap();
                println!("DEBUG after encryption of transport state message 2: {:?}", &buffer_2_final);
                stream.write_all(&buffer_2_final).unwrap()
    },
        Err(e) => eprintln!("Error on connection: {}", e),
        }
    }
}
