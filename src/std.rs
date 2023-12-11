use super::{Encoding, Error, Frame, Header, Packet, Read, Seek, Write};
use std::{fmt, io::SeekFrom};

impl<W> Write for W
where
    W: std::io::Write,
{
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.write_all(buf).or(Err(Error::Write))
    }
}

impl<R> Read for R
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<u32, Error> {
        u32::try_from(self.read(buf).map_err(|_| Error::Read)?).map_err(|_| Error::Data)
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)
            .map(|()| buf[0])
            .or(Err(Error::Read))
    }
}

impl<S> Seek for S
where
    S: std::io::Seek,
{
    fn seek(&mut self, offset: u32) -> Result<(), Error> {
        let new_offset = u32::try_from(
            self.seek(SeekFrom::Start(u64::from(offset)))
                .or(Err(Error::Data))?,
        )
        .map_err(|_| Error::Data)?;
        if offset != new_offset {
            return Err(Error::Read);
        }
        Ok(())
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:8} {}", self.encoding, self.frame)
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}
