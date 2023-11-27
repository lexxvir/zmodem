// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::*;

pub struct ReadWriteLog<RW> {
    inner: BufReader<RW>,
}

impl<RW: Read + Write> ReadWriteLog<RW> {
    pub fn new(rw: RW) -> ReadWriteLog<RW> {
        ReadWriteLog {
            inner: BufReader::new(rw),
        }
    }
}

impl<R: Read> Read for ReadWriteLog<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let r = self.inner.read(buf)?;
        Ok(r)
    }
}

impl<R: Read> BufRead for ReadWriteLog<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let r = self.inner.fill_buf()?;
        Ok(r)
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

impl<RW: Write + Read> Write for ReadWriteLog<RW> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.get_mut().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.get_mut().flush()
    }
}
