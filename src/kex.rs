use crate::algorithms::*;
use crate::misc::{Builder, Parser};
use failure::Error;
use rand::rngs::OsRng;
use rand::Rng;

fn generate_cookie() -> [u8; 16] {
    let mut rand = OsRng::new().unwrap();
    let mut cookie: [u8; 16] = [0; 16];
    rand.try_fill(&mut cookie).unwrap();
    cookie
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
        let server_host_key_algorithms = self
            .server_host_key_algorithms
            .join(",")
            .as_bytes()
            .to_vec();
        let encryption_algorithms_client_to_server = self
            .encryption_algorithms_client_to_server
            .join(",")
            .as_bytes()
            .to_vec();
        let encryption_algorithms_server_to_client = self
            .encryption_algorithms_server_to_client
            .join(",")
            .as_bytes()
            .to_vec();
        let mac_algorithms_client_to_server = self
            .mac_algorithms_client_to_server
            .join(",")
            .as_bytes()
            .to_vec();
        let mac_algorithms_server_to_client = self
            .mac_algorithms_server_to_client
            .join(",")
            .as_bytes()
            .to_vec();
        let compression_algorithms_client_to_server = self
            .compression_algorithms_client_to_server
            .join(",")
            .as_bytes()
            .to_vec();
        let compression_algorithms_server_to_client = self
            .compression_algorithms_server_to_client
            .join(",")
            .as_bytes()
            .to_vec();
        let languages_client_to_server = self
            .languages_client_to_server
            .join(",")
            .as_bytes()
            .to_vec();
        let languages_server_to_client = self
            .languages_server_to_client
            .join(",")
            .as_bytes()
            .to_vec();

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

    /// build the struct and adds packet length and padding
    pub fn build_as_payload(self) -> Vec<u8> {
        Builder::new().write_vec(self.build()).as_payload()
    }
}

impl Default for KexInit {
    fn default() -> KexInit {
        Self {
            ssh_msg_kexinit: 20,
            cookie: generate_cookie().to_vec(),
            kex_algorithms: vec![KeyExchangeAlgorithm::to_string(
                &KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg,
            )],
            server_host_key_algorithms: vec![HostKeyAlgorithm::to_string(
                &HostKeyAlgorithm::SshEd25519,
            )],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::to_string(
                &EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom,
            )],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::to_string(
                &EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom,
            )],
            mac_algorithms_client_to_server: Vec::new(),
            mac_algorithms_server_to_client: Vec::new(),
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::to_string(
                &CompressionAlgorithm::None,
            )],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::to_string(
                &CompressionAlgorithm::None,
            )],
            languages_client_to_server: Vec::new(),
            languages_server_to_client: Vec::new(),
            first_kex_packet_follows: false,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_kex_init_1() {
        let hex_query = "0000056c0414f4c0f2055a147858d36fa896189312a20000010d637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d630000016665636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7373682d656432353531392c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273610000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000000000000000000000000000000000";
        let hex_query = hex::decode(hex_query).unwrap();
        let kex_init = KexInit::parse(&hex_query).unwrap();

        assert_eq!(
            kex_init,
            KexInit {
                ssh_msg_kexinit: 20,
                cookie: hex::decode("f4c0f2055a147858d36fa896189312a2").unwrap(),
                kex_algorithms: vec![
                    "curve25519-sha256".to_string(),
                    "curve25519-sha256@libssh.org".to_string(),
                    "ecdh-sha2-nistp256".to_string(),
                    "ecdh-sha2-nistp384".to_string(),
                    "ecdh-sha2-nistp521".to_string(),
                    "diffie-hellman-group-exchange-sha256".to_string(),
                    "diffie-hellman-group16-sha512".to_string(),
                    "diffie-hellman-group18-sha512".to_string(),
                    "diffie-hellman-group14-sha256".to_string(),
                    "diffie-hellman-group14-sha1".to_string(),
                    "ext-info-c".to_string()
                ],
                server_host_key_algorithms: vec![
                    "ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
                    "ecdsa-sha2-nistp384-cert-v01@openssh.com".to_string(),
                    "ecdsa-sha2-nistp521-cert-v01@openssh.com".to_string(),
                    "ssh-ed25519-cert-v01@openssh.com".to_string(),
                    "rsa-sha2-512-cert-v01@openssh.com".to_string(),
                    "rsa-sha2-256-cert-v01@openssh.com".to_string(),
                    "ssh-rsa-cert-v01@openssh.com".to_string(),
                    "ecdsa-sha2-nistp256".to_string(),
                    "ecdsa-sha2-nistp384".to_string(),
                    "ecdsa-sha2-nistp521".to_string(),
                    "ssh-ed25519".to_string(),
                    "rsa-sha2-512".to_string(),
                    "rsa-sha2-256".to_string(),
                    "ssh-rsa".to_string()
                ],
                encryption_algorithms_client_to_server: vec![
                    "chacha20-poly1305@openssh.com".to_string(),
                    "aes128-ctr".to_string(),
                    "aes192-ctr".to_string(),
                    "aes256-ctr".to_string(),
                    "aes128-gcm@openssh.com".to_string(),
                    "aes256-gcm@openssh.com".to_string()
                ],
                encryption_algorithms_server_to_client: vec![
                    "chacha20-poly1305@openssh.com".to_string(),
                    "aes128-ctr".to_string(),
                    "aes192-ctr".to_string(),
                    "aes256-ctr".to_string(),
                    "aes128-gcm@openssh.com".to_string(),
                    "aes256-gcm@openssh.com".to_string()
                ],
                mac_algorithms_client_to_server: vec![
                    "umac-64-etm@openssh.com".to_string(),
                    "umac-128-etm@openssh.com".to_string(),
                    "hmac-sha2-256-etm@openssh.com".to_string(),
                    "hmac-sha2-512-etm@openssh.com".to_string(),
                    "hmac-sha1-etm@openssh.com".to_string(),
                    "umac-64@openssh.com".to_string(),
                    "umac-128@openssh.com".to_string(),
                    "hmac-sha2-256".to_string(),
                    "hmac-sha2-512".to_string(),
                    "hmac-sha1".to_string()
                ],
                mac_algorithms_server_to_client: vec![
                    "umac-64-etm@openssh.com".to_string(),
                    "umac-128-etm@openssh.com".to_string(),
                    "hmac-sha2-256-etm@openssh.com".to_string(),
                    "hmac-sha2-512-etm@openssh.com".to_string(),
                    "hmac-sha1-etm@openssh.com".to_string(),
                    "umac-64@openssh.com".to_string(),
                    "umac-128@openssh.com".to_string(),
                    "hmac-sha2-256".to_string(),
                    "hmac-sha2-512".to_string(),
                    "hmac-sha1".to_string()
                ],
                compression_algorithms_client_to_server: vec![
                    "none".to_string(),
                    "zlib@openssh.com".to_string(),
                    "zlib".to_string()
                ],
                compression_algorithms_server_to_client: vec![
                    "none".to_string(),
                    "zlib@openssh.com".to_string(),
                    "zlib".to_string()
                ],
                languages_client_to_server: Vec::new(),
                languages_server_to_client: Vec::new(),
                first_kex_packet_follows: false,
                reserved: 0,
            }
        );
    }

    #[test]
    pub fn test_build_kex_init_1() {
        let hex_query = "0000056c0414f4c0f2055a147858d36fa896189312a20000010d637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d630000016665636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7373682d656432353531392c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273610000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000000000000000000000000000000000";
        let hex_query = hex::decode(hex_query).unwrap();
        let kex_init = KexInit::parse(&hex_query).unwrap().build();

        // exclude lenght and padding
        assert_eq!(kex_init, hex_query[5..(hex_query.len() - 4)].to_vec());
    }
}
