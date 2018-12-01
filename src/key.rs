use failure::Error;
use std::fs::File;
use std::io::Read;

pub struct Ed25519Key {
    private: [u8; 64],
    public: [u8; 32],
}

impl Ed25519Key {
    pub fn new(file_path: &str) -> Result<Self, Error> {
        let mut ed25519 = String::new();
        let mut file = File::open(file_path)?;
        file.read_to_string(&mut ed25519)?;
        Ed25519Key::from_string(ed25519)
    }

    pub fn from_string(private_key: String) -> Result<Self, Error> {
        let private = ssh_keys::openssh::parse_private_key(&private_key)?;
        let public = match private[0].public_key() {
            ssh_keys::PublicKey::Ed25519(v) => v,
            _ => panic!(),
        };
        let private = match private[0] {
            ssh_keys::PrivateKey::Ed25519(v) => v,
            _ => panic!(),
        };

        Ok(Ed25519Key { private, public })
    }

    pub fn private(&self) -> Vec<u8> {
        self.private.to_vec()
    }

    pub fn public(&self) -> Vec<u8> {
        self.public.to_vec()
    }
}
