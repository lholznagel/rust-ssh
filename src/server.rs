use crate::kex::*;
use crate::kexdh::*;
use crate::version::*;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Version,
    KeyExchangeInit,
    DiffiHellmanKeyExchange,
    Message,
}

impl Default for State {
    fn default() -> Self {
        State::Version
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Transport {
    pub state: State,
    pub client_version: Version,
    pub server_version: Version,
}

#[derive(Debug)]
pub struct SSHServer {
    tcp_listener: TcpStream,
}

impl SSHServer {
    pub fn new(tcp_listener: TcpStream) -> Self {
        //std::mem::forget(Box::new(42));
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut transport = Transport::default();

        let mut client_kex = Vec::new();
        let mut server_kex = Vec::new();

        loop {
            let mut message = Vec::new();
            let mut buffer = [0; 4];

            let _ = self.tcp_listener.read(&mut buffer).unwrap();
            if buffer[0] == 83 && buffer[1] == 83 && buffer[2] == 72 {
                let mut message_buffer = vec![0; 252]; // 256 - the 4 byte already read
                let _ = self.tcp_listener.read(&mut message_buffer).unwrap();
                message.append(&mut buffer.to_vec());
                message.append(&mut message_buffer.to_vec());
            } else if buffer[0] == 0 && buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 0 {
                // FIXME
                std::process::exit(0);
            } else {
                let packet_length = unsafe { std::mem::transmute::<[u8; 4], u32>(buffer) }.to_be();
                let mut message_buffer = vec![0; packet_length as usize];
                self.tcp_listener.read_exact(&mut message_buffer).unwrap();
                message.append(&mut buffer.to_vec());
                message.append(&mut message_buffer.to_vec());
            }

            match transport.state {
                State::Version => {
                    // version string will be max 256 chars long
                    match Version::parse(&message) {
                        Ok(x) => {
                            transport.client_version = x;
                            transport.server_version = Version::default();

                            self.tcp_listener
                                .write_all(&Version::default().get_bytes())
                                .unwrap();
                            transport.state = State::KeyExchangeInit;
                            continue;
                        }
                        _ => panic!("Expected protocol version exchange."),
                    };
                }
                State::KeyExchangeInit => {
                    KexInit::parse(&message).unwrap();
                    match KexInit::parse(&message) {
                        Ok(client_msg_parsed) => {
                            client_kex = client_msg_parsed.build();
                            server_kex = KexInit::default().build();

                            let response = KexInit::default().build_as_payload();
                            self.tcp_listener.write_all(&response).unwrap();
                            transport.state = State::DiffiHellmanKeyExchange;
                            continue;
                        }
                        _ => println!("Not KexInit"),
                    };
                }
                State::DiffiHellmanKeyExchange => {
                    match KexDh::parse(
                        &message,
                        DiffiHellman {
                            client_identifier: transport.client_version.filtered(),
                            server_identifier: transport.server_version.filtered(),
                            client_kex: client_kex.clone(),
                            server_kex: server_kex.clone(),
                        },
                    ) {
                        Ok(x) => {
                            self.tcp_listener.write_all(&x.build()).unwrap();
                            transport.state = State::Message;
                            continue;
                        }
                        _ => println!("Not KexDh"),
                    };
                }
                State::Message => {
                    std::process::exit(0);
                }
            }
        }
    }
}
