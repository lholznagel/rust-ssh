use byteorder::{BigEndian, WriteBytesExt};
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct Builder {
    bytes: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn write_u8(mut self, value: u8) -> Self {
        self.bytes.write_u8(value).unwrap();
        self
    }

    pub fn write_u32(mut self, value: u32) -> Self {
        self.bytes.write_u32::<BigEndian>(value).unwrap();
        self
    }

    pub fn write_vec(mut self, mut vec: Vec<u8>) -> Self {
        self.bytes.append(&mut vec);
        self
    }

    pub fn write_mpint(self, mut vec: Vec<u8>) -> Self {
        let mut extra = Vec::new();

        if vec[0] >= 128 {
            extra.push(0);
        }

        if vec[0] == 0 {
            vec.remove(0);
        }

        self.write_u32(vec.len() as u32 + extra.len() as u32)
            .write_vec(extra)
            .write_vec(vec)
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

impl Display for Builder {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(
            f,
            "  00  01  02  03  04  05  06  07  08  09  10  11  12  13  14  15 "
        )?;
        writeln!(
            f,
            "|---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|"
        )?;

        let mut added = 0;
        let inner_cursor = self.bytes.clone();
        for val in inner_cursor {
            match val {
                n if n < 10 => write!(f, "|  {:?}", val)?,
                n if n < 100 => write!(f, "| {:?}", val)?,
                _ => write!(f, "|{:?}", val)?,
            };

            added += 1;
            if added > 0 && added % 16 == 0 {
                added = 0;
                writeln!(f, "|")?;
            }
        }

        write!(f, "|  0|")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_mpint_0() {
        let builder = Builder::new()
            .write_mpint(vec![0])
            .build();

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
        let builder = Builder::new()
            .write_mpint(vec![128])
            .build();

        assert_eq!(builder, hex::decode("000000020080").unwrap());
    }
}
