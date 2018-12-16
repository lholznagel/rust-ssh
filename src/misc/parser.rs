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
        let mut buffer = [0; 1];
        self.buffer.read_exact(&mut buffer)?;
        Ok(buffer[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let mut buffer = [0; 4];
        self.buffer.read_exact(&mut buffer)?;
        Ok(unsafe { std::mem::transmute::<[u8; 4], u32>(buffer) }.to_be())
    }

    pub fn read_length(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; length];
        self.buffer.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_list(&mut self) -> Result<Vec<String>, Error> {
        let length = self.read_u32()?;
        let list = String::from_utf8(self.read_length(length as usize)?)?;

        if !list.is_empty() {
            let splitted = list.split(',').map(|x| x.to_string()).collect::<Vec<_>>();
            Ok(splitted)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn read_string(&mut self) -> Result<String, Error> {
        let length = self.read_u32()?;
        Ok(String::from_utf8(self.read_length(length as usize)?)?)
    }

    pub fn skip(&mut self, length: usize) -> Result<(), Error> {
        self.read_length(length)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_u32() {
        let parser = Parser::new(&[0, 19, 49, 140]).read_u32().unwrap();
        assert_eq!(parser, 1257868);

        let builder = Parser::new(&[9, 250, 230, 76]).read_u32().unwrap();
        assert_eq!(builder, 167437900);
    }
}
