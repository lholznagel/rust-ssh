mod builder;
mod parser;

use self::builder::Builder;
use self::parser::Parser;
use failure::{format_err, Error};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Copy, Clone, Debug)]
struct ProtocolVersionExchange;

impl ProtocolVersionExchange {
    pub fn parse(data: &[u8; 2048]) -> Result<Self, Error> {
        // check the first three bytes for the String SSH
        // TODO: the first line does not have to be the SSH string
        if data[0] == 83 && data[1] == 83 && data[2] == 72 {
            Ok(Self {})
        } else {
            Err(format_err!(""))
        }
    }

    pub fn build() -> Vec<u8> {
        // TODO variable name
        // SSH-2.0-TEST0.1.0
        vec![
            83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 48, 46, 49, 46, 48, 13, 10,
        ]
    }
}

#[derive(Clone, Debug, Default)]
struct AlgorithmNegotiation {
    pub packet_length: u32,
    pub padding_length: u8,
    pub ssh_msg_kexinit: u8,
    pub cookie: Vec<u8>,
    pub kex_algorithms: String,
    pub server_host_key_algorithms: String,
    pub encryption_algorithms_client_to_server: String,
    pub encryption_algorithms_server_to_client: String,
    pub mac_algorithms_client_to_server: String,
    pub mac_algorithms_server_to_client: String,
    pub compression_algorithms_client_to_server: String,
    pub compression_algorithms_server_to_client: String,
    pub languages_client_to_server: String,
    pub languages_server_to_client: String,
    pub first_kex_packet_follows: bool,
}

impl AlgorithmNegotiation {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut parser = Parser::new(data);
        Ok(Self {
            packet_length: parser.read_u32()?,
            padding_length: parser.read_u8()?,
            ssh_msg_kexinit: parser.read_u8()?,
            cookie: parser.read_length(16)?,
            kex_algorithms: parser.read_list()?,
            server_host_key_algorithms: parser.read_list()?,
            encryption_algorithms_client_to_server: parser.read_list()?,
            encryption_algorithms_server_to_client: parser.read_list()?,
            mac_algorithms_client_to_server: parser.read_list()?,
            mac_algorithms_server_to_client: parser.read_list()?,
            compression_algorithms_client_to_server: parser.read_list()?,
            compression_algorithms_server_to_client: parser.read_list()?,
            languages_client_to_server: parser.read_list()?,
            languages_server_to_client: parser.read_list()?,
            first_kex_packet_follows: parser.read_u8()? == 1,
        })
    }

    // TODO optimize
    pub fn build() -> Vec<u8> {
        let kex = String::from("curve25519-sha256");
        let server_host_key = String::from("ecdsa-sha2-nistp256-cert-v01@openssh.com");
        let encryption_algorithm = String::from("chacha20-poly1305@openssh.com");
        let mac_algorithm = String::from("hmac-sha2-256");
        let compression = String::from("none");

        let key_exchange = Builder::new()
            .write_u8(20)
            .write_vec(generate_cookie().to_vec())
            .write_u32(kex.len() as u32)
            .write_vec(kex.as_bytes().to_vec())
            .write_u32(server_host_key.len() as u32)
            .write_vec(server_host_key.as_bytes().to_vec())
            .write_u32(encryption_algorithm.len() as u32)
            .write_vec(encryption_algorithm.as_bytes().to_vec())
            .write_u32(encryption_algorithm.len() as u32)
            .write_vec(encryption_algorithm.as_bytes().to_vec())
            .write_u32(mac_algorithm.len() as u32)
            .write_vec(mac_algorithm.as_bytes().to_vec())
            .write_u32(mac_algorithm.len() as u32)
            .write_vec(mac_algorithm.as_bytes().to_vec())
            .write_u32(compression.len() as u32)
            .write_vec(compression.as_bytes().to_vec())
            .write_u32(compression.len() as u32)
            .write_vec(compression.as_bytes().to_vec())
            // language
            .write_u32(0)
            // language
            .write_u32(0)
            // first kex packet
            .write_u8(0)
            // reserved
            .write_u32(0)
            .build();

        let mut padding = (key_exchange.len() % 8) as u8;
        if padding < 4 {
            padding = padding + 8;
        }

        let builder = Builder::with_capacity(key_exchange.len());
        builder
            .write_u32(key_exchange.len() as u32 + 1)
            .write_u8(padding)
            .write_vec(key_exchange)
            .write_vec(vec![0; padding as usize])
            .build()
    }
}

pub struct SSHTransport {
    tcp_listener: TcpStream,
}

impl SSHTransport {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        let mut protocol_exchange = false;
        let mut key_exchange = false;

        loop {
            let mut buffer = [0; 2048];
            self.tcp_listener.read(&mut buffer).unwrap();

            if !protocol_exchange {
                match ProtocolVersionExchange::parse(&buffer) {
                    Ok(_) => {
                        self.tcp_listener
                            .write(&ProtocolVersionExchange::build())
                            .unwrap();
                        protocol_exchange = true;
                        continue;
                    }
                    _ => println!("Not ProtocolVersionExchange"),
                };
            }

            if !key_exchange {
                match AlgorithmNegotiation::parse(&buffer) {
                    Ok(_) => {
                        self.tcp_listener
                            .write(&AlgorithmNegotiation::build())
                            .unwrap();
                        key_exchange = true;
                        continue;
                    }
                    _ => println!("Not AlgorithmNegotiation"),
                };
            }
        }
    }
}

// TODO randomg
pub fn generate_cookie() -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
