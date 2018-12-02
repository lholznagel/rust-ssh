use failure::{format_err, Error};

const SSH_START: [u8; 3] = [83, 83, 72];
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    pub identifier: Vec<u8>,
}

impl Version {
    pub fn new(version: String) -> Result<Self, Error> {
        let mut version = version;
        match version.chars().rev().nth(1) {
            Some('\r') => (),
            _ => version.push_str("\r"),
        };

        match version.chars().rev().nth(0) {
            Some('\n') => (),
            _ => version.push_str("\n"),
        };

        Ok(Self {
            identifier: version.as_bytes().to_vec(),
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let result = data
            .windows(SSH_START.len())
            .position(|window| window == SSH_START);
        let result = match result {
            Some(x) => x,
            None    => return Err(format_err!("Not a version string"))
        };

        let data = data
            .to_vec()
            .into_iter()
            .filter(|x| *x != 0)
            .skip(result)
            .map(|x| x)
            .collect::<Vec<u8>>();

        Ok(Self { identifier: data })
    }

    pub fn filtered(&self) -> Vec<u8> {
        self.identifier
            .clone()
            .into_iter()
            .filter(|x| *x != 10 && *x != 13)
            .collect()
    }

    pub fn get_bytes(self) -> Vec<u8> {
        self.identifier
    }
}

impl Default for Version {
    fn default() -> Self {
        let mut version = String::from("SSH-2.0-rssh_");
        version.push_str(VERSION);

        Self::new(version).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_001() {
        let data = "SSH-2.0-test-0.1.0\r\n";
        let result = Version::parse(&data.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_002() {
        let data = "SSH-2.0-test-0.1.0 Some_comment\r\n";
        let result = Version::parse(&data.as_bytes());
        assert!(result.is_ok());
    }
   
    #[test]
    pub fn test_003() {
        let data = "Some\r\nrandom\r\nthoughts\r\non\r\nthe\r\nssh\r\nversion\r\n SSH-2.0-test-0.1.0\r\n".as_bytes().to_vec();
        let result = Version::parse(&data);
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_004() {
        let result = Version::new(String::from("SSH-2.0-test-0.1.0\r\n"));
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_005() {
        let result = Version::new(String::from("SSH-2.0-test-0.1.0"));
        assert!(result.is_ok());
    }
}
