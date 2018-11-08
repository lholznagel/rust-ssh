pub enum HostKeyAlgorithm {
    SshEd25519
}

impl HostKeyAlgorithm {
    pub fn from_str(s: &str) -> Option<HostKeyAlgorithm> {
        match s {
            "ssh-ed25519" => Some(HostKeyAlgorithm::SshEd25519),
            _ => None,
        }
    }

    pub fn to_str(e: HostKeyAlgorithm) -> String {
        match e {
            HostKeyAlgorithm::SshEd25519 => String::from("ssh-ed25519")
        }
    }

    pub fn to_vec(e: HostKeyAlgorithm) -> Vec<u8> {
        HostKeyAlgorithm::to_str(e).as_bytes().to_vec()
    }
}

pub enum KeyExchangeAlgorithm {
    Curve25519Sha256AtLibsshDotOrg
}

impl KeyExchangeAlgorithm {
    pub fn from_str(s: &str) -> Option<KeyExchangeAlgorithm> {
        match s {
            "curve25519-sha256@libssh.org" => Some(KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg),
            _ => None,
        }
    }

    pub fn to_str(e: KeyExchangeAlgorithm) -> String {
        match e {
            KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg => String::from("curve25519-sha256@libssh.org")
        }
    }

    pub fn to_vec(e: KeyExchangeAlgorithm) -> Vec<u8> {
        KeyExchangeAlgorithm::to_str(e).as_bytes().to_vec()
    }
}

pub enum EncryptionAlgorithm {
    Chacha20Poly1305AtOpensshDotCom
}

impl EncryptionAlgorithm {
    pub fn from_str(s: &str) -> Option<EncryptionAlgorithm> {
        match s {
            "chacha20-poly1305@openssh.com" => Some(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom),
            _ => None,
        }
    }

    pub fn to_str(e: EncryptionAlgorithm) -> String {
        match e {
            EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom => String::from("chacha20-poly1305@openssh.com")
        }
    }

    pub fn to_vec(e: EncryptionAlgorithm) -> Vec<u8> {
        EncryptionAlgorithm::to_str(e).as_bytes().to_vec()
    }
}

pub enum CompressionAlgorithm {
    None
}

impl CompressionAlgorithm {
    pub fn from_str(s: &str) -> Option<CompressionAlgorithm> {
        match s {
            "none" => Some(CompressionAlgorithm::None),
            _ => None,
        }
    }

    pub fn to_str(e: CompressionAlgorithm) -> String {
        match e {
            CompressionAlgorithm::None => String::from("none")
        }
    }

    pub fn to_vec(e: CompressionAlgorithm) -> Vec<u8> {
        CompressionAlgorithm::to_str(e).as_bytes().to_vec()
    }
}