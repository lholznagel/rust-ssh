use crate::algorithm_negotiation::*;
use crate::diffie_hellman_exchange::*;
use crate::protocol_version_exchange::*;
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct SSHServer {
    tcp_listener: TcpStream,
}

impl SSHServer {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut protocol_exchange = false;
        let mut payload = false;
        let mut diffie = false;

        let mut client_identifier = Vec::new();
        let mut server_identifier = Vec::new();
        let mut client_kex = Vec::new();
        let mut server_kex = Vec::new();

        loop {
            let mut buffer = [0; 2048];
            self.tcp_listener.read(&mut buffer).unwrap();

            if !protocol_exchange {
                match ProtocolVersionExchange::parse(&buffer) {
                    Ok(x) => {
                        client_identifier = x
                            .identifier
                            .into_iter()
                            .filter(|x| *x != 10 && *x != 13)
                            .collect();

                        let response = ProtocolVersionExchange::build();
                        server_identifier = response
                            .clone()
                            .into_iter()
                            .filter(|x| *x != 10 && *x != 13)
                            .collect();
                        self.tcp_listener.write(&response).unwrap();
                        protocol_exchange = true;
                        continue;
                    }
                    _ => println!("Not ProtocolVersionExchange"),
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
                    _ => println!("Not AlgorithmNegotiation"),
                };
            } else if !diffie {
                match DiffieHellmanKeyExchange::parse(
                    &buffer,
                    DiffiHellman {
                        client_identifier: client_identifier.clone(),
                        server_identifier: server_identifier.clone(),
                        client_kex: client_kex.clone(),
                        server_kex: server_kex.clone(),
                    },
                ) {
                    Ok(x) => {
                        self.tcp_listener.write(&x.build()).unwrap();
                        diffie = true;
                        continue;
                    }
                    _ => println!("Not DiffieHellmanKeyExchange"),
                };
            } else {
                std::process::exit(0);
            }
        }
    }
}
