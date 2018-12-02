#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyExchangeAlgorithm {
    Curve25519Sha256AtLibsshDotOrg,
    Unknown,
}

impl KeyExchangeAlgorithm {
    pub fn to_str(e: KeyExchangeAlgorithm) -> String {
        match e {
            KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg => {
                String::from("curve25519-sha256@libssh.org")
            }
            KeyExchangeAlgorithm::Unknown => String::from(""),
        }
    }

    pub fn to_vec(e: KeyExchangeAlgorithm) -> Vec<u8> {
        KeyExchangeAlgorithm::to_str(e).as_bytes().to_vec()
    }

    #[allow(dead_code)]
    pub fn from_str(e: &str) -> KeyExchangeAlgorithm {
        match e {
            "curve25519-sha256@libssh.org" => KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg,
            _ => KeyExchangeAlgorithm::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostKeyAlgorithm {
    SshEd25519,
    Unknown,
}

impl HostKeyAlgorithm {
    pub fn to_str(e: HostKeyAlgorithm) -> String {
        match e {
            HostKeyAlgorithm::SshEd25519 => String::from("ssh-ed25519"),
            HostKeyAlgorithm::Unknown => String::from(""),
        }
    }

    pub fn to_vec(e: HostKeyAlgorithm) -> Vec<u8> {
        HostKeyAlgorithm::to_str(e).as_bytes().to_vec()
    }

    #[allow(dead_code)]
    pub fn from_str(e: &str) -> HostKeyAlgorithm {
        match e {
            "ssh-ed25519" => HostKeyAlgorithm::SshEd25519,
            _ => HostKeyAlgorithm::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    Chacha20Poly1305AtOpensshDotCom,
    Unknown,
}

impl EncryptionAlgorithm {
    pub fn to_str(e: EncryptionAlgorithm) -> String {
        match e {
            EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom => {
                String::from("chacha20-poly1305@openssh.com")
            }
            EncryptionAlgorithm::Unknown => String::from(""),
        }
    }

    pub fn to_vec(e: EncryptionAlgorithm) -> Vec<u8> {
        EncryptionAlgorithm::to_str(e).as_bytes().to_vec()
    }

    #[allow(dead_code)]
    pub fn from_str(e: &str) -> EncryptionAlgorithm {
        match e {
            "chacha20-poly1305@openssh.com" => EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom,
            _ => EncryptionAlgorithm::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CompressionAlgorithm {
    None,
}

impl CompressionAlgorithm {
    pub fn to_str(e: CompressionAlgorithm) -> String {
        match e {
            CompressionAlgorithm::None => String::from("none"),
        }
    }

    pub fn to_vec(e: CompressionAlgorithm) -> Vec<u8> {
        CompressionAlgorithm::to_str(e).as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn eq_curve25519() {
        assert_eq!(
            KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg,
            KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg
        );
    }

    #[test]
    pub fn to_str_curve25519() {
        assert_eq!(
            KeyExchangeAlgorithm::to_str(KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg),
            "curve25519-sha256@libssh.org"
        );
    }

    #[test]
    pub fn to_vec_curve25519() {
        assert_eq!(
            KeyExchangeAlgorithm::to_vec(KeyExchangeAlgorithm::Curve25519Sha256AtLibsshDotOrg),
            "curve25519-sha256@libssh.org".as_bytes().to_vec()
        );
    }

    #[test]
    pub fn eq_ed25519() {
        assert_eq!(HostKeyAlgorithm::SshEd25519, HostKeyAlgorithm::SshEd25519);
    }

    #[test]
    pub fn to_str_ed25519() {
        assert_eq!(
            HostKeyAlgorithm::to_str(HostKeyAlgorithm::SshEd25519),
            "ssh-ed25519"
        );
    }

    #[test]
    pub fn to_vec_ed25519() {
        assert_eq!(
            HostKeyAlgorithm::to_vec(HostKeyAlgorithm::SshEd25519),
            "ssh-ed25519".as_bytes().to_vec()
        );
    }

    #[test]
    pub fn eq_chacha_poly1305() {
        assert_eq!(
            EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom,
            EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom
        );
    }

    #[test]
    pub fn to_str_chacha_poly1305() {
        assert_eq!(
            EncryptionAlgorithm::to_str(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom),
            "chacha20-poly1305@openssh.com"
        );
    }

    #[test]
    pub fn to_vec_chacha_poly1305() {
        assert_eq!(
            EncryptionAlgorithm::to_vec(EncryptionAlgorithm::Chacha20Poly1305AtOpensshDotCom),
            "chacha20-poly1305@openssh.com".as_bytes().to_vec()
        );
    }
}
