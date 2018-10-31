use crate::builder::Builder;
use crate::parser::Parser;
use failure::Error;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

#[derive(Clone, Debug, Default)]
pub struct DiffiHellman {
    pub client_identifier: Vec<u8>,
    pub server_identifier: Vec<u8>,
    pub client_kex: Vec<u8>,
    pub server_kex: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct DiffieHellmanKeyExchange {
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
        // convert e to a array of 32 elements
        let mut e = [0; 32];
        for i in 0..32 {
            e[i] = self.e[i];
        }

        // random gen for the curve
        let mut curve_rand = rand::OsRng::new().unwrap();
        // generate the curve25519 secret
        let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        // generate the curve25519 public
        let curve_public = x25519_dalek::generate_public(&curve_secret);
        // shared diffie hellman key, combining the own secret with the client public
        let dh = x25519_dalek::diffie_hellman(&curve_secret, &e);

        // read the host key
        let mut ed25519 = String::new();
        let mut file = File::open("./resources/id_ed25519").unwrap();
        file.read_to_string(&mut ed25519).unwrap();
        let private = ssh_keys::openssh::parse_private_key(&ed25519).unwrap();
        let public = match private[0].public_key() {
            ssh_keys::PublicKey::Ed25519(v) => v,
            _ => panic!(),
        };
        let private = match private[0] {
            ssh_keys::PrivateKey::Ed25519(v) => v,
            _ => panic!(),
        };

        let hash = self.hash(
            public.to_vec(),
            curve_public.as_bytes().to_vec(),
            dh.to_vec(),
        );

        // create a signature of H
        let dh_signed = crypto::ed25519::signature(&hash, &private); // s

        let hash_algo = String::from("ssh-ed25519");
        let h = Builder::new()
            .write_u32(hash_algo.len() as u32)
            .write_vec(hash_algo.as_bytes().to_vec())
            .write_u32(dh_signed.len() as u32)
            .write_vec(dh_signed.to_vec())
            .build();

        let payload = Builder::new()
            // ssh_msg_kexdh
            .write_u8(31)
            // length + algo + length + key
            .write_u32(4 + 11 + 4 + 32)
            .write_u32(11)
            .write_vec(String::from("ssh-ed25519").as_bytes().to_vec())
            .write_u32(public.len() as u32)
            .write_vec(public.to_vec()) // K_S
            .write_u32(curve_public.to_bytes().len() as u32)
            .write_vec(curve_public.to_bytes().to_vec()) // f
            .write_u32(h.len() as u32)
            .write_vec(h) // s
            .build();

        let mut padding = ((4 + 1 + payload.len()) % 8) as u8;
        if padding < 4 {
            padding = 8 - padding;
        } else {
            padding = 8 + (8 - padding);
        }

        Builder::new()
            .write_u32(1 + payload.len() as u32 + padding as u32)
            .write_u8(padding)
            .write_vec(payload)
            .write_vec(vec![0; padding as usize])
            .build()
    }

    pub fn hash(self, host_key: Vec<u8>, f: Vec<u8>, dh: Vec<u8>) -> Vec<u8> {
        let builder = Builder::new()
            .write_vec(self.diffie_hellman.client_identifier)
            .write_vec(self.diffie_hellman.server_identifier)
            .write_u32(self.diffie_hellman.client_kex.len() as u32)
            .write_vec(self.diffie_hellman.client_kex)
            .write_u32(self.diffie_hellman.server_kex.len() as u32)
            .write_vec(self.diffie_hellman.server_kex)
            .write_vec(host_key)
            .write_vec(self.e)
            .write_vec(f)
            .write_mpint(dh)
            .build();

        let mut hasher = Sha256::new();
        hasher.input(&builder);
        hasher.result().as_slice().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test() {
        let client_secret_curve = [
            172, 248, 23, 55, 154, 161, 239, 222, 126, 150, 62, 5, 61, 116, 164, 194, 177, 126,
            177, 46, 176, 90, 207, 47, 122, 208, 236, 177, 209, 104, 95, 174,
        ];
        let client_public_curve = [
            240, 142, 149, 12, 110, 252, 185, 31, 240, 198, 137, 163, 240, 42, 110, 170, 159, 4,
            51, 233, 186, 45, 79, 187, 235, 16, 104, 70, 197, 254, 182, 39,
        ];
        let server_secret_curve = [
            166, 144, 70, 110, 80, 36, 186, 230, 1, 23, 12, 83, 71, 114, 94, 88, 68, 153, 87, 128,
            148, 80, 19, 10, 43, 167, 185, 172, 154, 245, 154, 28,
        ];
        let server_public_curve = [
            10, 65, 226, 208, 72, 85, 24, 85, 51, 119, 78, 164, 121, 217, 157, 229, 126, 183, 67,
            177, 137, 94, 215, 93, 55, 154, 241, 184, 126, 23, 69, 92,
        ];

        let server_ed25519 = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQAAAJg4AnndOAJ5
3QAAAAtzc2gtZWQyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQ
AAAEDHAmlg7DyqUT05PFBiPs77qBD5h6U1+RbZ38mEIVAWX4c4cr+fpISqTfOZSiykyO+Y
UoWSg/X10k+iHKWAY1VZAAAAEmxob2x6bmFnZWxAYW5hcmNoeQECAw==
        -----END OPENSSH PRIVATE KEY-----";
        let parsed_server_ed25519 = ssh_keys::openssh::parse_private_key(&server_ed25519).unwrap();
        let parsed_server_ed25519_public = match parsed_server_ed25519[0].public_key() {
            ssh_keys::PublicKey::Ed25519(v) => v,
            _ => panic!(),
        };

        let parsed_server_ed25519 = match parsed_server_ed25519[0] {
            ssh_keys::PrivateKey::Ed25519(v) => v,
            _ => panic!(),
        };

        let vc = vec![
            83, 83, 72, 45, 50, 46, 48, 45, 79, 112, 101, 110, 83, 83, 72, 95, 55, 46, 56,
        ];
        let vs = vec![
            83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 48, 46, 49, 46, 48,
        ];
        let ic = vec![
            168, 249, 79, 18, 103, 246, 196, 88, 202, 124, 59, 191, 24, 4, 171, 107, 0, 0, 1, 13,
            99, 117, 114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 44, 99, 117,
            114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 64, 108, 105, 98, 115,
            115, 104, 46, 111, 114, 103, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105,
            115, 116, 112, 50, 53, 54, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105,
            115, 116, 112, 51, 56, 52, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105,
            115, 116, 112, 53, 50, 49, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108,
            109, 97, 110, 45, 103, 114, 111, 117, 112, 45, 101, 120, 99, 104, 97, 110, 103, 101,
            45, 115, 104, 97, 50, 53, 54, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108,
            109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 54, 45, 115, 104, 97, 53, 49, 50, 44,
            100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111,
            117, 112, 49, 56, 45, 115, 104, 97, 53, 49, 50, 44, 100, 105, 102, 102, 105, 101, 45,
            104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 52, 45, 115, 104,
            97, 50, 53, 54, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110,
            45, 103, 114, 111, 117, 112, 49, 52, 45, 115, 104, 97, 49, 44, 101, 120, 116, 45, 105,
            110, 102, 111, 45, 99, 0, 0, 1, 102, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45,
            110, 105, 115, 116, 112, 50, 53, 54, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64, 111,
            112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100, 115, 97, 45, 115,
            104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 45, 99, 101, 114, 116, 45, 118,
            48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100, 115,
            97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 45, 99, 101, 114,
            116, 45, 118, 48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 115,
            115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64,
            111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 114, 115, 97, 45, 115, 104,
            97, 50, 45, 53, 49, 50, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64, 111, 112, 101, 110,
            115, 115, 104, 46, 99, 111, 109, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45, 50, 53,
            54, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46,
            99, 111, 109, 44, 115, 115, 104, 45, 114, 115, 97, 45, 99, 101, 114, 116, 45, 118, 48,
            49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100, 115, 97,
            45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 44, 101, 99, 100, 115,
            97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 44, 101, 99, 100,
            115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 44, 115, 115,
            104, 45, 101, 100, 50, 53, 53, 49, 57, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45, 53,
            49, 50, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 115, 115, 104, 45,
            114, 115, 97, 0, 0, 0, 108, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121,
            49, 51, 48, 53, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101,
            115, 49, 50, 56, 45, 99, 116, 114, 44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44,
            97, 101, 115, 50, 53, 54, 45, 99, 116, 114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99,
            109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 50, 53,
            54, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0,
            108, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64, 111,
            112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 49, 50, 56, 45, 99,
            116, 114, 44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44, 97, 101, 115, 50, 53, 54,
            45, 99, 116, 114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99, 109, 64, 111, 112, 101,
            110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 50, 53, 54, 45, 103, 99, 109,
            64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 213, 117, 109, 97,
            99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111,
            109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116, 109, 64, 111, 112, 101, 110,
            115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50,
            53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44,
            104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 101, 116, 109, 64, 111,
            112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97,
            49, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44,
            117, 109, 97, 99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109,
            44, 117, 109, 97, 99, 45, 49, 50, 56, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99,
            111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 104, 109, 97,
            99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49,
            0, 0, 0, 213, 117, 109, 97, 99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110,
            115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116,
            109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45,
            115, 104, 97, 50, 45, 50, 53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115,
            104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45,
            101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109,
            97, 99, 45, 115, 104, 97, 49, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104,
            46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115,
            104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 64, 111, 112, 101, 110,
            115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50,
            53, 54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 104, 109, 97,
            99, 45, 115, 104, 97, 49, 0, 0, 0, 26, 110, 111, 110, 101, 44, 122, 108, 105, 98, 64,
            111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 122, 108, 105, 98, 0, 0, 0,
            26, 110, 111, 110, 101, 44, 122, 108, 105, 98, 64, 111, 112, 101, 110, 115, 115, 104,
            46, 99, 111, 109, 44, 122, 108, 105, 98, 0,
        ];
        let is = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 99, 117, 114, 118, 101,
            50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 0, 0, 0, 11, 115, 115, 104, 45, 101,
            100, 50, 53, 53, 49, 57, 0, 0, 0, 29, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111,
            108, 121, 49, 51, 48, 53, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0,
            0, 0, 29, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64,
            111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 13, 104, 109, 97, 99, 45,
            115, 104, 97, 50, 45, 50, 53, 54, 0, 0, 0, 13, 104, 109, 97, 99, 45, 115, 104, 97, 50,
            45, 50, 53, 54, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0,
        ];
        let ks = parsed_server_ed25519_public;
        let e = client_public_curve;
        let f = server_public_curve;
        let k = x25519_dalek::diffie_hellman(&server_secret_curve, &client_public_curve);

        let diffie_hellman_exchange = DiffieHellmanKeyExchange {
            packet_length: 0,
            padding_length: 0,
            ssh_msg_kexdh: 0,
            e: e.to_vec(),
            diffie_hellman: DiffiHellman {
                client_identifier: vc.clone(),
                server_identifier: vs.clone(),
                client_kex: ic.clone(),
                server_kex: is.clone(),
            },
        };

        let server_hash = diffie_hellman_exchange.hash(ks.to_vec(), f.to_vec(), k.to_vec());
        let server_sign = crypto::ed25519::signature(&server_hash, &parsed_server_ed25519);

        let ic_len = Builder::new().write_u32(ic.len() as u32).build();
        let is_len = Builder::new().write_u32(is.len() as u32).build();

        let client_dh = x25519_dalek::diffie_hellman(&client_secret_curve, &server_public_curve);
        let mut hasher = Sha256::new(); // H
        hasher.input(&vc); // V_C
        hasher.input(&vs); // S_C
        hasher.input(&ic_len);
        hasher.input(&ic); // I_C
        hasher.input(&is_len);
        hasher.input(&is); // I_S
        hasher.input(&ks); // K_S
        hasher.input(&e); // e
        hasher.input(&f); // f
        hasher.input(&client_dh); // K
        let client_hash = hasher.result().as_slice().to_vec();

        assert_eq!(client_hash, server_hash);
        assert!(crypto::ed25519::verify(
            &client_hash,
            &parsed_server_ed25519_public,
            &server_sign
        ));
    }
}
