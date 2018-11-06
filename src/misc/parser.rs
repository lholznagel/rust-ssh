use byteorder::{BigEndian, ReadBytesExt};
use failure::Error;
use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct Parser<'a> {
    buffer: Cursor<&'a [u8]>,
}

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            buffer: Cursor::new(bytes),
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.buffer.read_u8()?)
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(self.buffer.read_u32::<BigEndian>()?)
    }

    pub fn read_length(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; length];
        self.buffer.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_list(&mut self) -> Result<String, Error> {
        let length = self.read_u32()?;
        Ok(String::from_utf8(self.read_length(length as usize)?)?)
    }
}
