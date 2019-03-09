use crate::misc::Parser;
use failure::{format_err, Error};
use std::fs::File;
use std::io::Read;

pub struct Ed25519Key {
    pub author: String,
    pub cipher: String,
    pub kdf: String,
    pub key_type: String,
    pub number_of_keys: u32,
    pub public: Vec<u8>,
    private: Vec<u8>,
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

        let decoded = base64::decode(&private_key)?;

        let end_key_type = decoded.iter().position(|&x| x == 0).unwrap();
        let key_type = String::from_utf8(decoded[..end_key_type].to_vec())?;

        let mut parser = Parser::new(&decoded[end_key_type + 1..]);
        let cipher = parser.read_string().unwrap();
        let kdf = parser.read_string().unwrap();

        if cipher != "none" {
            return Err(format_err!("Cipher not supported"));
        }

        if kdf != "none" {
            return Err(format_err!("KDF not supported"));
        }

        let _ = parser.skip(4);
        let number_of_keys = parser.read_u32()?;
        let _ = parser.skip(4);

        let ed25519 = parser.read_string().unwrap();
        if ed25519 != "ssh-ed25519" {
            return Err(format_err!("Only ssh-ed25519 keys are supported"));
        }

        // we wait for the second public key
        let _ = parser.skip(4);
        let _ = parser.skip(32);

        let _ = parser.skip(4); // remaining payload
        let _ = parser.skip(8); // unsure

        let _ = parser.skip(4); // the key type again
        let _ = parser.skip(11); // just skip it

        let _ = parser.skip(4); // unsure
        let _ = parser.skip(32);

        let _ = parser.skip(4); // length of private and public key
        let private = parser.read_length(32)?;
        let public = parser.read_length(32)?;

        let author = parser.read_string()?;

        Ok(Ed25519Key {
            author,
            cipher,
            kdf,
            number_of_keys,
            key_type,
            private,
            public,
        })
    }

    pub fn signature(&self) -> Vec<u8> {
        let mut private = self.private.clone();
        let mut public = self.public.clone();

        let mut result = Vec::new();
        result.append(&mut private);
        result.append(&mut public);
        result
    }

    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parser() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQAAAJg4AnndOAJ5
3QAAAAtzc2gtZWQyNTUxOQAAACCHOHK/n6SEqk3zmUospMjvmFKFkoP19dJPohylgGNVWQ
AAAEDHAmlg7DyqUT05PFBiPs77qBD5h6U1+RbZ38mEIVAWX4c4cr+fpISqTfOZSiykyO+Y
UoWSg/X10k+iHKWAY1VZAAAAEmxob2x6bmFnZWxAYW5hcmNoeQECAw==
-----END OPENSSH PRIVATE KEY-----";

        let expected_public = vec![
            135, 56, 114, 191, 159, 164, 132, 170, 77, 243, 153, 74, 44, 164, 200, 239, 152, 82,
            133, 146, 131, 245, 245, 210, 79, 162, 28, 165, 128, 99, 85, 89,
        ];
        let expected_private = vec![
            199, 2, 105, 96, 236, 60, 170, 81, 61, 57, 60, 80, 98, 62, 206, 251, 168, 16, 249, 135,
            165, 53, 249, 22, 217, 223, 201, 132, 33, 80, 22, 95,
        ];

        let ed25519 = Ed25519Key::from_string(String::from(key)).unwrap();
        assert_eq!(expected_public, ed25519.public);
        assert_eq!(expected_private, ed25519.private);
    }
}
