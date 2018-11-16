use failure::{format_err, Error};

#[derive(Clone, Debug)]
pub struct ProtocolVersionExchange {
    pub identifier: Vec<u8>,
}

impl ProtocolVersionExchange {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let data = data
                .to_vec()
                .into_iter()
                .filter(|x| *x != 0)
                .map(|x| x)
                .collect::<Vec<u8>>();

        if data.len() > 255 {
            return Err(format_err!("Protocol version too long!"));
        }
        // check the first three bytes for the String SSH
        // TODO: the first line does not have to be the SSH string
        if data[0] == 83 && data[1] == 83 && data[2] == 72 {
            Ok(Self {
                identifier: data,
            })
        } else {
            Err(format_err!(""))
        }
    }

    pub fn build() -> Vec<u8> {
        "SSH-2.0-rssh_0.1.0\r\n".as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_001() {
        let data = "SSH-2.0-test-0.1.0\r\n";
        let result = ProtocolVersionExchange::parse(&data.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_002() {
        let data = "SSH-2.0-test-0.1.0 Some_comment\r\n";
        let result = ProtocolVersionExchange::parse(&data.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_003() {
        let mut data = "SSH-2.0-test-0.1.0\r\n".as_bytes().to_vec();
        data.append(&mut vec![1; 236]);
        let result = ProtocolVersionExchange::parse(&data);
        assert!(result.is_err());
    }
}