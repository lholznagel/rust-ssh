use crate::misc::payload::wrap_payload;
use crate::misc::{Builder, Parser};
use failure::Error;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use rand::rngs::OsRng;

#[derive(Clone, Debug, Default)]
pub struct DiffiHellman {
    pub client_identifier: Vec<u8>,
    pub server_identifier: Vec<u8>,
    pub client_kex: Vec<u8>,
    pub server_kex: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct KexDh {
    pub packet_length: u32,
    pub padding_length: u8,
    pub ssh_msg_kexdh: u8,
    pub e: Vec<u8>,
    pub diffie_hellman: DiffiHellman,
}

impl KexDh {
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

    pub fn build_client() -> Vec<u8> {
        // random gen for the curve
        let mut curve_rand = OsRng::new().unwrap();
        // generate the curve25519 secret
        let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        // generate the curve25519 public
        let curve_public = x25519_dalek::generate_public(&curve_secret);

        let payload = Builder::new()
            .write_u8(30) // message_code
            .write_u32(32)
            .write_vec(curve_public.as_bytes().to_vec()) // e
            .build();

        wrap_payload(payload)
    }

    pub fn build(self) -> Vec<u8> {
        // convert e to a array of 32 elements
        let mut e = [0; 32];
        for i in 0..32 {
            e[i] = self.e[i];
        }

        // random gen for the curve
        let mut curve_rand = OsRng::new().unwrap();
        // generate the curve25519 secret
        let curve_secret = x25519_dalek::generate_secret(&mut curve_rand);
        // generate the curve25519 public
        let f = x25519_dalek::generate_public(&curve_secret);
        // shared diffie hellman key, combining the own secret with the client public
        let k = x25519_dalek::diffie_hellman(&curve_secret, &e);

        // read the host key
        let mut ed25519 = String::new();
        let mut file = File::open("./resources/id_ed25519").unwrap();
        file.read_to_string(&mut ed25519).unwrap();
        let (private, public) = self.parse_ed25519(ed25519);

        let hash = self.clone().hash(
            public.to_vec(),
            f.as_bytes().to_vec(),
            k.to_vec(),
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

        //let payload = Builder::new()
        Builder::new()
            .write_u32(196)
            .write_u8(16)
            // ssh_msg_kexdh
            .write_u8(31)
            // length + algo + length + key
            .write_u32(4 + 11 + 4 + 32)
            .write_u32(11)
            .write_vec(String::from("ssh-ed25519").as_bytes().to_vec())
            .write_u32(public.len() as u32)
            .write_vec(public.to_vec()) // K_S
            .write_u32(f.to_bytes().len() as u32)
            .write_vec(f.to_bytes().to_vec()) // f
            .write_u32(h.len() as u32)
            .write_vec(h) // s
            .write_vec(vec![0; 16])
            .build()

        //wrap_payload(payload)
    }

    pub fn hash(self, host_key: Vec<u8>, f: Vec<u8>, k: Vec<u8>) -> Vec<u8> {
        println!("{:?}", ::std::str::from_utf8(&self.diffie_hellman.client_identifier));
        println!("{:?}", ::std::str::from_utf8(&self.diffie_hellman.server_identifier));

        let builder = Builder::new()
            .write_u32(self.diffie_hellman.client_identifier.len() as u32)
            .write_vec(self.diffie_hellman.client_identifier) // V_C
            .write_u32(self.diffie_hellman.server_identifier.len() as u32)
            .write_vec(self.diffie_hellman.server_identifier) // V_S
            .write_u32(self.diffie_hellman.client_kex.len() as u32)
            .write_vec(self.diffie_hellman.client_kex) // I_C
            .write_u32(self.diffie_hellman.server_kex.len() as u32)
            .write_vec(self.diffie_hellman.server_kex) // I_S
            .write_u32(host_key.len() as u32)
            .write_vec(host_key) // K_S
            .write_u32(self.e.len() as u32)
            .write_vec(self.e) // e
            .write_u32(f.len() as u32)
            .write_vec(f) // f
            .write_u32(k.len() as u32)
            .write_vec(k) // K
            .build();

        let hasher = Sha256::digest(&builder);
        println!("{:?}", hex::encode(hasher.clone()));
        hasher.as_slice().to_vec()
    }

    fn parse_ed25519(&self, private_key: String) -> ([u8; 64], [u8; 32]) {
        let private = ssh_keys::openssh::parse_private_key(&private_key).unwrap();
        let public = match private[0].public_key() {
            ssh_keys::PublicKey::Ed25519(v) => v,
            _ => panic!(),
        };
        let private = match private[0] {
            ssh_keys::PrivateKey::Ed25519(v) => v,
            _ => panic!(),
        };
        (private, public)
    }
}

#[cfg(test)]
mod tests {
    use crate::kex::KexInit;
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    pub fn validate_hash() {
        let server_ed25519 = String::from("-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQAAAJg4AnndOAJ5
3QAAAAtzc2gtZWQyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQ
AAAEDHAmlg7DyqUT05PFBiPs77qBD5h6U1+RbZ38mEIVAWX4c4cr+fpISqTfOZSiykyO+Y
UoWSg/X10k+iHKWAY1VZAAAAEmxob2x6bmFnZWxAYW5hcmNoeQECAw==
        -----END OPENSSH PRIVATE KEY-----");

        let mut curve_rand = OsRng::new().unwrap();
        let client_secret_curve = x25519_dalek::generate_secret(&mut curve_rand);
        let e = x25519_dalek::generate_public(&client_secret_curve);

        let server_secret_curve = x25519_dalek::generate_secret(&mut curve_rand);
        let f = x25519_dalek::generate_public(&server_secret_curve);

        let vc = String::from("SSH-2.0-OpenSSH_7.9").as_bytes().to_vec();
        let vs = String::from("SSH-2.0-rssh-0.1.0").as_bytes().to_vec();

        let ic = KexInit::build();
        let is = KexInit::build();

        let kex_dh = KexDh {
            packet_length: 0,
            padding_length: 0,
            ssh_msg_kexdh: 0,
            e: e.as_bytes().to_vec(),
            diffie_hellman: DiffiHellman {
                client_identifier: vc.clone(),
                server_identifier: vs.clone(),
                client_kex: ic.clone(),
                server_kex: is.clone(),
            },
        };

        let (ed25519_private, ks) = kex_dh.parse_ed25519(server_ed25519);
        let k = x25519_dalek::diffie_hellman(&server_secret_curve, &e.as_bytes());

        let server_hash = kex_dh.hash(ks.to_vec(), f.as_bytes().to_vec(), k.to_vec());
        let server_sign = crypto::ed25519::signature(&server_hash, &ed25519_private);
        let server_dh = x25519_dalek::diffie_hellman(&server_secret_curve, &e.as_bytes());

        // ---------- CLIENT ----------
        let client_dh = x25519_dalek::diffie_hellman(&client_secret_curve, &f.as_bytes());
        let hash_builder = Builder::new()
            .write_u32(vc.len() as u32)
            .write_vec(vc) // V_C
            .write_u32(vs.len() as u32)
            .write_vec(vs) // V_S
            .write_u32(ic.len() as u32)
            .write_vec(ic) // I_C
            .write_u32(is.len() as u32)
            .write_vec(is) // I_S
            .write_u32(ks.len() as u32)
            .write_vec(ks.to_vec()) // K_S
            .write_u32(e.as_bytes().len() as u32)
            .write_vec(e.as_bytes().to_vec()) // e
            .write_u32(f.as_bytes().len() as u32)
            .write_vec(f.as_bytes().to_vec()) // f
            .write_u32(client_dh.len() as u32)
            .write_vec(client_dh.to_vec()) // K
            .build();

        let mut hasher = Sha256::new();
        hasher.input(&hash_builder);

        let client_hash = hasher.result().as_slice().to_vec();
        assert_eq!(client_hash, server_hash);
        assert_eq!(client_dh, server_dh);
        assert!(crypto::ed25519::verify(&client_hash, &ks, &server_sign));
    }
}
