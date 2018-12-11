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
        std::mem::forget(Box::new(42));
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut transport = Transport::default();

        let mut client_kex = Vec::new();
        let mut server_kex = Vec::new();

        loop {
            let mut buffer = [0; 2048];

            self.tcp_listener.read(&mut buffer).unwrap();

            match transport.state {
                State::Version => {
                    // version string will be max 256 chars long
                    match Version::parse(&buffer[0..256]) {
                        Ok(x) => {
                            transport.client_version = x;
                            transport.server_version = Version::default();

                            self.tcp_listener
                                .write(&Version::default().get_bytes())
                                .unwrap();
                            transport.state = State::KeyExchangeInit;
                            continue;
                        }
                        _ => panic!("Expected protocol version exchange."),
                    };
                }
                State::KeyExchangeInit => {
                    KexInit::parse(&buffer).unwrap();
                    match KexInit::parse(&buffer) {
                        Ok(client_msg_parsed) => {
                            let response = KexInit::build();

                            client_kex = client_msg_parsed.build_hash_payload();
                            server_kex = KexInit::parse(&response).unwrap().build_hash_payload();

                            self.tcp_listener.write(&response).unwrap();
                            transport.state = State::DiffiHellmanKeyExchange;
                            continue;
                        }
                        _ => println!("Not KexInit"),
                    };
                }
                State::DiffiHellmanKeyExchange => {
                    match KexDh::parse(
                        &buffer,
                        DiffiHellman {
                            client_identifier: transport.client_version.filtered(),
                            server_identifier: transport.server_version.filtered(),
                            client_kex: client_kex.clone(),
                            server_kex: server_kex.clone(),
                        },
                    ) {
                        Ok(x) => {
                            self.tcp_listener.write(&x.build()).unwrap();
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
