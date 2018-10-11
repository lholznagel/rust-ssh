mod parser;

use self::parser::Parser;
use failure::{format_err, Error};
use std::io::{Read, Write};
use std::net::TcpStream;

enum Ciphers {}

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
}

pub struct SSHTransport {
    tcp_listener: TcpStream,
}

impl SSHTransport {
    pub fn new(tcp_listener: TcpStream) -> Self {
        Self { tcp_listener }
    }

    pub fn accept(mut self) {
        loop {
            let mut buffer = [0; 2048];
            self.tcp_listener.read(&mut buffer).unwrap();

            match ProtocolVersionExchange::parse(&buffer) {
                Ok(_) => {
                    println!("ProtocolVersionExchange");
                    self.tcp_listener
                        .write(&ProtocolVersionExchange::build())
                        .unwrap();
                    continue;
                }
                _ => println!("Not ProtocolVersionExchange"),
            };

            match AlgorithmNegotiation::parse(&buffer) {
                Ok(a) => println!("{:?}", a.kex_algorithms),
                _ => println!("Not AlgorithmNegotiation"),
            };
        }
    }
}
