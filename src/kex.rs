use crate::algorithms::*;
use crate::misc::{Builder, Parser};
use failure::Error;
use rand::rngs::OsRng;
use rand::Rng;

fn generate_cookie() -> [u8; 16] {
    let mut rand = OsRng::new().unwrap();
    let mut cookie: [u8; 16] = [0; 16];
    rand.try_fill(&mut cookie).unwrap();
    return cookie;
}

#[derive(Clone, Debug)]
pub struct KexInit {
    pub ssh_msg_kexinit: u8,
    pub cookie: Vec<u8>,
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

impl KexInit {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut parser = Parser::new(data);

        parser.skip(4)?; // packet length
        parser.skip(1)?; // padding

        Ok(Self {
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
            reserved: 0,
        })
    }
    
    pub fn build(self) -> Vec<u8> {
        let kex_algorithms = self.kex_algorithms.join(",").as_bytes().to_vec();
        let server_host_key_algorithms = self.server_host_key_algorithms.join(",").as_bytes().to_vec();
        let encryption_algorithms_client_to_server = self.encryption_algorithms_client_to_server.join(",").as_bytes().to_vec();
        let encryption_algorithms_server_to_client = self.encryption_algorithms_server_to_client.join(",").as_bytes().to_vec();
        let mac_algorithms_client_to_server = self.mac_algorithms_client_to_server.join(",").as_bytes().to_vec();
        let mac_algorithms_server_to_client = self.mac_algorithms_server_to_client.join(",").as_bytes().to_vec();
        let compression_algorithms_client_to_server = self.compression_algorithms_client_to_server.join(",").as_bytes().to_vec();
        let compression_algorithms_server_to_client = self.compression_algorithms_server_to_client.join(",").as_bytes().to_vec();
        let languages_client_to_server = self.languages_client_to_server.join(",").as_bytes().to_vec();
        let languages_server_to_client = self.languages_server_to_client.join(",").as_bytes().to_vec();

        Builder::new()
            .write_u8(20)
            .write_vec(self.cookie)
            .write_u32(kex_algorithms.len() as u32)
            .write_vec(kex_algorithms)
            .write_u32(server_host_key_algorithms.len() as u32)
            .write_vec(server_host_key_algorithms)
            .write_u32(encryption_algorithms_client_to_server.len() as u32)
            .write_vec(encryption_algorithms_client_to_server)
            .write_u32(encryption_algorithms_server_to_client.len() as u32)
            .write_vec(encryption_algorithms_server_to_client)
            .write_u32(mac_algorithms_client_to_server.len() as u32)
            .write_vec(mac_algorithms_client_to_server)
            .write_u32(mac_algorithms_server_to_client.len() as u32)
            .write_vec(mac_algorithms_server_to_client)
            .write_u32(compression_algorithms_client_to_server.len() as u32)
            .write_vec(compression_algorithms_client_to_server)
            .write_u32(compression_algorithms_server_to_client.len() as u32)
            .write_vec(compression_algorithms_server_to_client)
            .write_u32(languages_client_to_server.len() as u32)
            .write_vec(languages_client_to_server)
            .write_u32(languages_server_to_client.len() as u32)
            .write_vec(languages_server_to_client)
            .write_u8(self.first_kex_packet_follows as u8)
            .write_u32(0)
            .build()
    }

    pub fn build_as_payload(self) -> Vec<u8> {
        Builder::new()
            .write_vec(self.build())
            .as_payload()
    }
}

impl Default for KexInit {
    fn default() -> KexInit {
        Self {
            ssh_msg_kexinit: 20,
            cookie: generate_cookie().to_vec(),
            kex_algorithms: vec![KeyExchangeAlgorithm::to_string(KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg)],
            server_host_key_algorithms: vec![HostKeyAlgorithm::to_string(HostKeyAlgorithm::SshEd25519)],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::to_string(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom)],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::to_string(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom)],
            mac_algorithms_client_to_server: Vec::new(),
            mac_algorithms_server_to_client: Vec::new(),
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::to_string(CompressionAlgorithm::None)],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::to_string(CompressionAlgorithm::None)],
            languages_client_to_server: Vec::new(),
            languages_server_to_client: Vec::new(),
            first_kex_packet_follows: false,
            reserved: 0,
        }
    }
}