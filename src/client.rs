use crate::algorithm_negotiation::*;
use crate::diffie_hellman_exchange::*;
use crate::protocol_version_exchange::*;
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct SSHClient {
    tcp_listener: TcpStream,
}

impl SSHClient {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn connect(mut self) {
        let protocol_version_exchange = ProtocolVersionExchange::build();
        self.tcp_listener.write(&protocol_version_exchange).unwrap();

        let mut client_identifier = Vec::new();
        let mut server_identifier = Vec::new();
        let mut client_kex = Vec::new();
        let mut server_kex = Vec::new();

        let mut protocol_exchange = false;
        let mut algorithm_negotiation = false;
        let mut diffie_hellman = false;

        loop {
            let mut buffer = [0; 2048];
            self.tcp_listener.read(&mut buffer).unwrap();

            if !protocol_exchange {
                match ProtocolVersionExchange::parse(&buffer) {
                    Ok(x) => {
                        server_identifier = x
                            .identifier
                            .into_iter()
                            .filter(|x| *x != 10 && *x != 13)
                            .collect();

                        let response = ProtocolVersionExchange::build();
                        client_identifier = response
                            .clone()
                            .into_iter()
                            .filter(|x| *x != 10 && *x != 13)
                            .collect();

                        let algorithm = AlgorithmNegotiation::build();
                        self.tcp_listener.write(&algorithm).unwrap();
                        protocol_exchange = true;
                        continue;
                    }
                    _ => println!("Not ProtocolVersionExchange"),
                };
            } else if !algorithm_negotiation {
                match AlgorithmNegotiation::parse(&buffer) {
                    Ok(x) => {
                        let response = AlgorithmNegotiation::build();
                        client_kex = AlgorithmNegotiation::parse(&response)
                            .unwrap()
                            .build_hash_payload();
                        server_kex = x.build_hash_payload();

                        self.tcp_listener
                            .write(&DiffieHellmanKeyExchange::build_client())
                            .unwrap();
                        algorithm_negotiation = true;
                        continue;
                    }
                    _ => println!("Not AlgorithmNegotiation"),
                };
            } else if !diffie_hellman {
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
                        diffie_hellman = true;
                        std::process::exit(0);
                    }
                    _ => println!("Not DiffieHellmanKeyExchange"),
                };
            } else {
                std::process::exit(0);
            }
        }
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
                match AlgorithmNegotiation::parse(&buffer) {
                    Ok(x) => {
                        let response = AlgorithmNegotiation::build();

                        client_kex = x.build_hash_payload();
                        server_kex = AlgorithmNegotiation::parse(&response)
                            .unwrap()
                            .build_hash_payload();

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
