mod builder;
mod parser;

use self::builder::Builder;
use self::parser::Parser;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use failure::{format_err, Error};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Clone, Debug, Default)]
struct DiffiHellman {
    pub client_identifier: Vec<u8>,
    pub server_identifier: Vec<u8>,
    pub client_kex: Vec<u8>,
    pub server_kex: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ProtocolVersionExchange {
    identifier: Vec<u8>,
}

impl ProtocolVersionExchange {
    pub fn parse(data: &[u8; 2048]) -> Result<Self, Error> {
        // check the first three bytes for the String SSH
        // TODO: the first line does not have to be the SSH string
        if data[0] == 83 && data[1] == 83 && data[2] == 72 {
            Ok(Self {
                identifier: data
                    .to_vec()
                    .iter()
                    .filter(|x| **x != 0)
                    .map(|x| *x)
                    .collect::<Vec<u8>>(),
            })
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
    pub complete_data: Vec<u8>,
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
            complete_data: data.to_vec().clone(),
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
        let server_host_key = String::from("ssh-ed25519");
        let encryption_algorithm = String::from("chacha20-poly1305@openssh.com");
        let mac_algorithm = String::from("hmac-sha2-256");
        let compression = String::from("none");

        let payload = Builder::new()
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

        // 4 -> packet length, 1 -> padding length
        let mut padding = ((4 + 1 + payload.len()) % 8) as u8;
        if padding < 4 {
            padding = 8 - padding;
        }

        let builder = Builder::with_capacity(payload.len());
        builder
            // 1 -> padding length
            .write_u32(1 + payload.len() as u32 + padding as u32)
            .write_u8(padding)
            .write_vec(payload)
            .write_vec(vec![0; padding as usize])
            .build()
    }
}

#[derive(Clone, Debug, Default)]
struct DiffieHellmanKeyExchange {
    pub packet_length: u32,
    pub padding_length: u8,
    pub ssh_msg_kexdh: u8,
    pub e: Vec<u8>,
    pub diffie_hellman: DiffiHellman,
}

impl DiffieHellmanKeyExchange {
    pub fn parse(data: &[u8], diffie_hellman: DiffiHellman) -> Result<Self, Error> {
        let mut parser = Parser::new(data);
        let packet_length = parser.read_u32()?;
        let padding_length = parser.read_u8()?;
        let ssh_msg_kexdh = parser.read_u8()?;
        let length_e = parser.read_u32()?;
        let e = parser.read_length(length_e as usize)?;

        Ok(Self {
            packet_length,
            padding_length,
            ssh_msg_kexdh,
            e,
            diffie_hellman,
        })
    }

    pub fn build(self) -> Vec<u8> {
        let mut public = [0; 32];
        for i in 0..32 {
            public[i] = self.e[i];
        }

        let mut curve_rand = rand::OsRng::new().unwrap();
        let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        let curve_public = x25519_dalek::generate_public(&curve_secret);
        let dh = x25519_dalek::diffie_hellman(&curve_secret, &public);

        let mut host_key = String::new();
        let mut file = File::open("./resources/id_ed25519.pub").unwrap();
        file.read_to_string(&mut host_key).unwrap();

        // TODO parse key
        let host_key = host_key.replace("ssh-ed25519 ", "").replace("\n", "");
        let host_key = base64::decode(&host_key).unwrap();
        let host_key = host_key[(4 + 11)..host_key.len()].to_vec();

        let mut hasher = Sha256::new();
        hasher.input(&self.diffie_hellman.client_identifier);
        hasher.input(&self.diffie_hellman.server_identifier);
        hasher.input(&self.diffie_hellman.client_kex);
        hasher.input(&self.diffie_hellman.server_kex);
        hasher.input(&host_key.clone());
        hasher.input(&self.e);
        hasher.input(&curve_public.to_bytes());
        hasher.input(&dh);

        let mut hash = vec![0; hasher.output_bits()];
        hasher.result(&mut hash);

        let payload = Builder::new()
            // ssh_msg_kexdh
            .write_u8(31)
            // length + algo + length + key
            .write_u32(4 + 11 + 4 + 32)
            .write_u32(11)
            .write_vec(String::from("ssh-ed25519").as_bytes().to_vec())
            .write_vec(host_key)
            .write_u32(32)
            .write_vec(curve_public.to_bytes().to_vec())
            .write_u32(hash.len() as u32)
            .write_vec(hash)
            .build();

        let mut padding = ((4 + 1 + payload.len()) % 8) as u8;
        if padding < 4 {
            padding = 8 - padding;
        }

        Builder::new()
            .write_u32(1 + payload.len() as u32 + padding as u32)
            .write_u8(padding)
            .write_vec(payload)
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
                        client_identifier = x.identifier;

                        let response = ProtocolVersionExchange::build();
                        server_identifier = response.clone();
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
                        client_kex = x.complete_data;
                        server_kex = response.clone();

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

// TODO randomg
pub fn generate_cookie() -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
