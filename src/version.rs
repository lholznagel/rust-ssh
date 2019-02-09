use failure::{format_err, Error};

/// Represents a SSH Version string
///
/// Example pattern:
/// `SSH-2.0-billsSSH_3.6.3q3 <CR> <LF>`
///
/// or
///
/// `SSH-2.0-billsSSH_2.6.3q3 <SP> comment <CR> <LF>
///
/// Using `Version::default()` returns a pattern for this library.
/// The pattern is: `SSH-2.0-rssh_{CURRENT_PKG_VERSION}`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    identifier: Vec<u8>,
}

impl Version {
    /// Creates a custom version string
    ///
    /// If the control chars CR or LF are missing, they will be added.
    pub fn new(version: String) -> Result<Self, Error> {
        let mut version = version;

        match version.chars().rev().nth(0) {
            Some('\n') => match version.chars().rev().nth(1) {
                Some('\r') => (),
                _ => version.push_str("\n"),
            },
            Some('\r') => version.push_str("\n"),
            _ => version.push_str("\r\n"),
        };

        Ok(Self {
            identifier: version.as_bytes().to_vec(),
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let ssh_start = [83, 83, 72];
        let result = data
            .windows(ssh_start.len())
            .position(|window| window == ssh_start);
        let result = match result {
            Some(x) => x,
            None => return Err(format_err!("Not a version string")),
        };

        let identifier = data
            .to_vec()
            .into_iter()
            .filter(|x| *x != 0)
            .skip(result)
            .collect::<Vec<u8>>();
        Ok(Self { identifier })
    }

    /// filters out CR and LF
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
        version.push_str(env!("CARGO_PKG_VERSION"));

        Self::new(version).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_new_version() {
        let v1 = Version::new(String::from("SSH-2.0-rssh_0.1.0")).unwrap();
        let v2 = Version::new(String::from("SSH-2.0-rssh_0.1.0\r")).unwrap();
        let v3 = Version::new(String::from("SSH-2.0-rssh_0.1.0\r\n")).unwrap();
        assert!(v1 == v2 && v2 == v3); // v1 == v2 == v3
    }

    #[test]
    pub fn test_parsing_version_string() {
        let data = "SSH-2.0-test-0.1.0\r\n";
        let result = Version::parse(&data.as_bytes());
        assert!(result.is_ok());
        assert!(result.unwrap().get_bytes() == data.as_bytes());
    }

    #[test]
    pub fn test_ssh_version_with_comment() {
        let data = "SSH-2.0-test-0.1.0 Some_comment\r\n";
        let result = Version::parse(&data.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_ssh_version_with_extra_lines() {
        let data =
            "Some\r\nrandom\r\nthoughts\r\non\r\nthe\r\nssh\r\nversion\r\nSSH-2.0-test-0.1.0\r\n"
                .as_bytes()
                .to_vec();
        let result = Version::parse(&data);
        assert!(result.is_ok());
    }
}
