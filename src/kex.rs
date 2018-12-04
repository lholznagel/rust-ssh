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

#[derive(Clone, Debug, Default)]
pub struct KexInit {
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
    pub reserved: Vec<u8>,
}

impl KexInit {
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
            reserved: vec![0; 4],
        })
    }

    pub fn build() -> Vec<u8> {
        let kex =
            KeyExchangeAlgorithm::to_vec(KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg);
        let server_host_key = HostKeyAlgorithm::to_vec(HostKeyAlgorithm::SshEd25519);
        let encryption_algorithm =
            EncryptionAlgorithm::to_vec(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom);
        let compression = CompressionAlgorithm::to_vec(CompressionAlgorithm::None);

        Builder::new()
            .write_u8(20)
            .write_vec(generate_cookie().to_vec())
            .write_u32(kex.len() as u32)
            .write_vec(kex)
            .write_u32(server_host_key.len() as u32)
            .write_vec(server_host_key)
            .write_u32(encryption_algorithm.len() as u32)
            .write_vec(encryption_algorithm.clone())
            .write_u32(encryption_algorithm.len() as u32)
            .write_vec(encryption_algorithm)
            .write_u32(0)
            .write_u32(0)
            .write_u32(compression.len() as u32)
            .write_vec(compression.clone())
            .write_u32(compression.len() as u32)
            .write_vec(compression)
            // language
            .write_u32(0)
            // language
            .write_u32(0)
            // first kex packet
            .write_u8(0)
            // reserved
            .write_u32(0)
            .as_payload()
    }

    pub fn build_hash_payload(self) -> Vec<u8> {
        Builder::new()
            .write_u8(20)
            .write_vec(self.cookie)
            .write_u32(self.kex_algorithms.len() as u32)
            .write_vec(self.kex_algorithms.as_bytes().to_vec())
            .write_u32(self.server_host_key_algorithms.len() as u32)
            .write_vec(self.server_host_key_algorithms.as_bytes().to_vec())
            .write_u32(self.encryption_algorithms_client_to_server.len() as u32)
            .write_vec(
                self.encryption_algorithms_client_to_server
                    .as_bytes()
                    .to_vec(),
            )
            .write_u32(self.encryption_algorithms_server_to_client.len() as u32)
            .write_vec(
                self.encryption_algorithms_server_to_client
                    .as_bytes()
                    .to_vec(),
            )
            .write_u32(self.mac_algorithms_client_to_server.len() as u32)
            .write_vec(self.mac_algorithms_client_to_server.as_bytes().to_vec())
            .write_u32(self.mac_algorithms_server_to_client.len() as u32)
            .write_vec(self.mac_algorithms_server_to_client.as_bytes().to_vec())
            .write_u32(self.compression_algorithms_client_to_server.len() as u32)
            .write_vec(
                self.compression_algorithms_client_to_server
                    .as_bytes()
                    .to_vec(),
            )
            .write_u32(self.compression_algorithms_server_to_client.len() as u32)
            .write_vec(
                self.compression_algorithms_server_to_client
                    .as_bytes()
                    .to_vec(),
            )
            .write_u32(self.languages_client_to_server.len() as u32)
            .write_vec(self.languages_client_to_server.as_bytes().to_vec())
            .write_u32(self.languages_server_to_client.len() as u32)
            .write_vec(self.languages_server_to_client.as_bytes().to_vec())
            .write_u8(self.first_kex_packet_follows as u8)
            .write_u32(0)
            .build()
    }
}
