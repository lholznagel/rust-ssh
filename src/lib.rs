use std::io::{Read, Write};
use std::net::TcpStream;

pub struct SSHTransport {
    tcp_listener: TcpStream,
}

impl SSHTransport {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut buffer = Vec::with_capacity(128);
        for byte in self.tcp_listener.try_clone().unwrap().bytes() {
            let byte = byte.unwrap();

            buffer.push(byte);
            if byte == 10 {
                break;
            }
        }

        println!(
            "{:?}, {}, {}",
            buffer.clone(),
            String::from_utf8(buffer).unwrap(),
            self.tcp_listener.peer_addr().unwrap()
        );

        self.tcp_listener
            .write(&[
                83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 48, 46, 49, 46, 48, 13, 10,
            ])
            .unwrap();
    }
}
