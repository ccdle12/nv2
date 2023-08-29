use std::io::{Read, Write};
use std::net::TcpListener;
use noise::{ChaCha20Poly1305, Responder, HandshakeOp};

fn main() {
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
