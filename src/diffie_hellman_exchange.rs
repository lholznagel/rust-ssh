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
        // generate the curve25519 secret
        let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        // generate the curve25519 public
        let curve_public = x25519_dalek::generate_public(&curve_secret);
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

        println!("{:?}", self.diffie_hellman.client_kex);

        // hash
        let mut hasher = Sha256::new(); // H
        hasher.input(&self.diffie_hellman.client_identifier); // V_C
        hasher.input(&self.diffie_hellman.server_identifier); // S_C
        hasher.input(&self.diffie_hellman.client_kex); // I_C
        hasher.input(&self.diffie_hellman.server_kex); // S_C
        hasher.input(&host_key.clone()); // K_S
        hasher.input(&self.e); // e
        hasher.input(&curve_public.to_bytes()); // f
        hasher.input(&dh); // K

        // combine the secret and public key to a keypair
        let mut keys = Vec::new();
        keys.append(&mut curve_secret.to_vec());
        keys.append(&mut curve_public.to_bytes().to_vec());
        let keypair = ed25519_dalek::Keypair::from_bytes(&keys).unwrap();
        // create a signature of H
        let dh_signed = keypair.sign::<Sha512>(&hasher.result()); // s

        let hash_algo = String::from("ssh-ed25519");
        let h = Builder::new()
            .write_u32(hash_algo.len() as u32)
            .write_vec(hash_algo.as_bytes().to_vec())
            .write_u32(dh_signed.to_bytes().len() as u32)
            .write_vec(dh_signed.to_bytes().to_vec())
            .build();

        let payload = Builder::new()
            // ssh_msg_kexdh
            .write_u8(31)
            // length + algo + length + key
            .write_u32(4 + 11 + 4 + 32)
            .write_u32(11)
            .write_vec(String::from("ssh-ed25519").as_bytes().to_vec())
            .write_vec(host_key) // K_S
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
}