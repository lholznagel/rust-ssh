use crate::kex::*;
use crate::kexdh::*;
use crate::version::*;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Transport {
    pub client_version: Version,
    pub server_version: Version,
}

pub struct SSHServer {
    tcp_listener: TcpStream,
}

impl SSHServer {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut transport = Transport::default();

        let mut protocol_exchange = false;
        let mut payload = false;
        let mut diffie = false;

        let mut client_kex = Vec::new();
        let mut server_kex = Vec::new();

        loop {
            let mut buffer = [0; 2048];

            self.tcp_listener.read(&mut buffer).unwrap();

            if !protocol_exchange {
                match Version::parse(&buffer[0..256]) {
                    Ok(x) => {
                        transport.client_version = x;
                        transport.server_version = Version::default();

                        let response = Version::default();
                        self.tcp_listener.write(&response.get_bytes()).unwrap();
                        protocol_exchange = true;
                        continue;
                    }
                    _ => println!("Not Protocol"),
                };
            } else if !payload {
                match KexInit::parse(&buffer) {
                    Ok(client_msg_parsed) => {
                        let response = KexInit::build();

                        client_kex = client_msg_parsed.build_hash_payload();
                        server_kex = KexInit::parse(&response).unwrap().build_hash_payload();

                        self.tcp_listener.write(&response).unwrap();
                        payload = true;
                        continue;
                    }
                    _ => println!("Not KexInit"),
                };
            } else if !diffie {
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
                        diffie = true;
                        continue;
                    }
                    _ => println!("Not KexDh"),
                };
            } else {
                std::process::exit(0);
            }
        }
    }
}
