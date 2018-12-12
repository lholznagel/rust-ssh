#[derive(Clone, Debug)]
pub struct Builder {
    bytes: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn write_u8(mut self, value: u8) -> Self {
        self.bytes.push(value);
        self
    }

    pub fn write_u32(mut self, value: u32) -> Self {
        let bytes: [u8; 4] = unsafe { ::std::mem::transmute(value.to_be()) };
        self.bytes.append(&mut bytes.to_vec());
        self
    }

    pub fn write_vec(mut self, mut vec: Vec<u8>) -> Self {
        self.bytes.append(&mut vec);
        self
    }

    pub fn write_mpint(self, mut vec: Vec<u8>) -> Self {
        let mut extra = false;

        if vec[0] >= 128 {
            extra = true;
        }

        if vec[0] == 0 {
            vec.remove(0);
        }

        if extra {
            self.write_u32(vec.len() as u32 + 1)
                .write_u8(0)
                .write_vec(vec)
        } else {
            self.write_u32(vec.len() as u32).write_vec(vec)
        }
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_payload(self) -> Vec<u8> {
        // packet length + padding
        let mut padding = ((4 + 1 + self.bytes.len()) % 8) as u8;
        if padding < 4 {
            padding = 8 - padding;
        } else {
            padding = 8 + (8 - padding);
        }

        Builder::new()
            // padding field + payload
            .write_u32(1 + self.bytes.len() as u32 + padding as u32)
            .write_u8(padding)
            .write_vec(self.bytes)
            .write_vec(vec![0; padding as usize])
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_mpint_0() {
        let builder = Builder::new().write_mpint(vec![0]).build();

        assert_eq!(builder, hex::decode("00000000").unwrap());
    }

    #[test]
    pub fn test_mpint_1() {
        let builder = Builder::new()
            .write_mpint(vec![9, 163, 120, 249, 178, 227, 50, 167])
            .build();

        assert_eq!(builder, hex::decode("0000000809a378f9b2e332a7").unwrap());
    }

    #[test]
    pub fn test_mpint_2() {
        let builder = Builder::new().write_mpint(vec![128]).build();

        assert_eq!(builder, hex::decode("000000020080").unwrap());
    }

    #[test]
    pub fn test_u32() {
        let builder = Builder::new().write_u32(1257868).build();
        assert_eq!(builder, [0, 19, 49, 140]);

        let builder = Builder::new().write_u32(167437900).build();
        assert_eq!(builder, [9, 250, 230, 76]);
    }
}
