use failure::{format_err, Error};

#[derive(Clone, Debug)]
pub struct ProtocolVersionExchange {
    pub identifier: Vec<u8>,
}

impl ProtocolVersionExchange {
    pub fn parse(data: &[u8; 2048]) -> Result<Self, Error> {
        // check the first three bytes for the String SSH
        // TODO: the first line does not have to be the SSH string
        if data[0] == 83 && data[1] == 83 && data[2] == 72 {
            Ok(Self {
                identifier: data
                    .to_vec()
                    .into_iter()
                    .filter(|x| *x != 0)
                    .map(|x| x)
                    .collect::<Vec<u8>>(),
            })
        } else {
            Err(format_err!(""))
        }
    }

    pub fn build() -> Vec<u8> {
        // TODO variable name
        // SSH-2.0-TEST0.1.0
        vec![
            83, 83, 72, 45, 50, 46, 48, 45, 84, 69, 83, 84, 48, 46, 49, 46, 48, 13, 10,
        ]
    }
}
