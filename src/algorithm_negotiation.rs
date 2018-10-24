use crate::builder::Builder;
use crate::parser::Parser;
use failure::Error;

// TODO randomg
pub fn generate_cookie() -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

#[derive(Clone, Debug, Default)]
pub struct AlgorithmNegotiation {
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
            reserved: vec![0; 4],
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

    pub fn build_payload(self) -> Vec<u8> {
        Builder::new()
            .write_u8(self.ssh_msg_kexinit)
            .write_vec(self.cookie.to_vec())
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
            .write_vec(self.reserved.to_vec())
            .build()
    }
}
