use crate::builder::Builder;
use crate::parser::Parser;
use failure::Error;
use sha2::{Digest, Sha256, Sha512};
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
        let mut public = [0; 32];
        for i in 0..32 {
            public[i] = self.e[i];
        }

        // random gen for the curve
        let mut curve_rand = rand::OsRng::new().unwrap();
        let ed_keypair = ed25519_dalek::Keypair::generate::<Sha512, _>(&mut curve_rand);
        // generate the curve25519 secret
        //let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        let curve_secret = ed_keypair.secret.to_bytes();
        // generate the curve25519 public
        //let curve_public = x25519_dalek::generate_public(&curve_secret);
        let curve_public = ed_keypair.public.to_bytes();
        // shared diffie hellman key, combining the own secret with the client public
        let dh = x25519_dalek::diffie_hellman(&curve_secret, &public);

        let mut host_key = String::new();
        // read the host key
        let mut file = File::open("./resources/id_ed25519.pub").unwrap();
        file.read_to_string(&mut host_key).unwrap();

        // "parses" the key and extracts the important information
        let host_key = host_key.replace("ssh-ed25519 ", "").replace("\n", "");
        let host_key = base64::decode(&host_key).unwrap();
        let host_key = host_key[(4 + 11)..host_key.len()].to_vec();
        println!("{:?}", host_key);

        let hash = self.hash(host_key.clone(), curve_public.to_vec(), dh.to_vec());
        // create a signature of H
        let dh_signed = self.sign(&ed_keypair, hash).to_bytes().to_vec(); // s

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
            .write_vec(host_key) // K_S
            .write_u32(curve_public.len() as u32)
            .write_vec(curve_public.to_vec()) // f
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

    pub fn sign(&self, keypair: &ed25519_dalek::Keypair, hash: Vec<u8>) -> ed25519_dalek::Signature {
        keypair.sign::<Sha512>(&hash)
    }

    pub fn hash(&self, host_key: Vec<u8>, curve_public: Vec<u8>, dh: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new(); // H
        hasher.input(&self.diffie_hellman.client_identifier); // V_C
        hasher.input(&self.diffie_hellman.server_identifier); // S_C
        hasher.input(&self.diffie_hellman.client_kex); // I_C
        hasher.input(&self.diffie_hellman.server_kex); // S_C
        hasher.input(&host_key.clone()); // K_S
        hasher.input(&self.e); // e
        hasher.input(&curve_public); // f
        hasher.input(&dh); // K
        hasher.result().as_slice().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_hash() {
        let their_keypair = vec![114, 81, 155, 115, 26, 23, 71, 238, 73, 129, 40, 214, 225, 137, 42, 54, 77, 147, 175, 134, 1, 17, 239, 115, 40, 116, 40, 77, 29, 248, 237, 43, 172, 53, 97, 87, 51, 161, 9, 197, 122, 37, 107, 85, 80, 23, 155, 33, 145, 227, 109, 56, 126, 133, 204, 130, 172, 106, 80, 122, 132, 159, 12, 67];
        let their_keypair = ed25519_dalek::Keypair::from_bytes(&their_keypair).unwrap();

        let our_keypair = vec![114, 58, 213, 139, 206, 102, 220, 38, 3, 249, 236, 186, 234, 15, 27, 14, 54, 202, 139, 102, 43, 162, 234, 93, 110, 198, 226, 244, 60, 211, 143, 95, 177, 103, 134, 162, 246, 234, 222, 222, 23, 213, 23, 100, 247, 173, 162, 138, 5, 162, 234, 195, 150, 169, 146, 143, 76, 206, 234, 196, 78, 98, 221, 127];
        let our_keypair = ed25519_dalek::Keypair::from_bytes(&our_keypair).unwrap();

        let diffie_helmann = DiffiHellman {
            client_identifier: vec![83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 95, 49],
            server_identifier: vec![83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 95, 50],
            client_kex: Vec::new(), // TODO
            server_kex: Vec::new() // TODO
        };

        let diffie_hellman_exchange = DiffieHellmanKeyExchange {
            packet_length: 0,
            padding_length: 0,
            ssh_msg_kexdh: 0,
            e: their_keypair.public.to_bytes().to_vec(),
            diffie_hellman: diffie_helmann,
        };

        let host_key = vec![0, 0, 0, 32, 135, 56, 114, 191, 159, 164, 132, 170, 77, 243, 153, 74, 44, 164, 200, 239, 152, 82, 133, 146, 131, 245, 245, 210, 79, 162, 28, 165, 128, 99, 85, 89];
        let dh = x25519_dalek::diffie_hellman(&our_keypair.secret.to_bytes(), &their_keypair.public.to_bytes());
        let hash = diffie_hellman_exchange.hash(host_key, our_keypair.public.to_bytes().to_vec(), dh.to_vec());
        let signed = diffie_hellman_exchange.sign(&our_keypair, hash.clone());

        let _ = our_keypair.verify::<Sha512>(&hash, &signed).unwrap();
    }
}
