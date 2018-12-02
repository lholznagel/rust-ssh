use crate::misc::Parser;
use failure::Error;
use std::fs::File;
use std::io::Read;

pub struct Ed25519Key {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl Ed25519Key {
    pub fn new(file_path: &str) -> Result<Self, Error> {
        let mut ed25519 = String::new();
        let mut file = File::open(file_path)?;
        file.read_to_string(&mut ed25519)?;
        Ed25519Key::from_string(ed25519)
    }

    pub fn from_string(private_key: String) -> Result<Self, Error> {
        let private_key = private_key.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "");
        let private_key = private_key.replace("-----END OPENSSH PRIVATE KEY-----", "");
        let private_key = private_key.replace("\n", "");
        let private_key = private_key.trim();

        let decoded = base64::decode(&private_key).unwrap();
        let end = decoded.iter().position(|&x| x == 0).unwrap();
        let key_type = ::std::str::from_utf8(&decoded[..end]).unwrap();
        if key_type != "openssh-key-v1" {
            panic!();
        }

        let mut parser = Parser::new(&decoded[end + 1..]);

        let cipher_name = parser.read_list().unwrap();
        let kdf_name = parser.read_list().unwrap();

        if cipher_name != "none" {
            panic!();
        }

        if kdf_name != "none" {
            panic!();
        }

        let _ = parser.skip(4);
        let _ = parser.read_u32().unwrap();
        let _ = parser.skip(4);
        let ed25519 = parser.read_list().unwrap();

        if ed25519 != "ssh-ed25519" {
            panic!();
        }

        let _ = parser.skip(3);
        let length_pub = parser.read_u8().unwrap();
        let _ = parser.skip(length_pub as usize);
        let _ = parser.skip(3);
        let _ = parser.skip(9);
        let _ = parser.skip(3);
        let _ = parser.skip(12);
        let _ = parser.skip(3);
        let _ = parser.skip(1);
        let _ = parser.skip(32);
        let _ = parser.skip(3);
        let _ = parser.skip(1);
        let public = parser.read_length(32).unwrap();
        let private = parser.read_length(32).unwrap();

        Ok(Ed25519Key { private, public })
    }

    pub fn private(&self) -> Vec<u8> {
        self.private.to_vec()
    }

    pub fn public(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    pub fn sign(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        result.append(&mut self.public.clone());
        result.append(&mut self.private.clone());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn unencrypted_ed25519() {
        let ed25519_key = String::from(
            "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQAAAJg4AnndOAJ5
3QAAAAtzc2gtZWQyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQ
AAAEDHAmlg7DyqUT05PFBiPs77qBD5h6U1+RbZ38mEIVAWX4c4cr+fpISqTfOZSiykyO+Y
UoWSg/X10k+iHKWAY1VZAAAAEmxob2x6bmFnZWxAYW5hcmNoeQECAw==
-----END OPENSSH PRIVATE KEY-----",
        );

        let ed25519 = Ed25519Key::from_string(ed25519_key).unwrap();
    }
}
