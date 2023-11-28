// SPDX-License-Identifier: MIT OR Apache-2.0
//! Manages end-point for the ZMODEM transfer protocol.

use std::io::{BufRead, BufReader, Read, Result, Write};

pub struct Port<P> {
    inner: BufReader<P>,
}

impl<P: Read> Port<P> {
    pub fn new(rw: P) -> Port<P> {
        Port {
            inner: BufReader::new(rw),
        }
    }
}

impl<R: Read> Read for Port<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let r = self.inner.read(buf)?;
        Ok(r)
    }
}

impl<R: Read> BufRead for Port<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let r = self.inner.fill_buf()?;
        Ok(r)
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

impl<P: Write + Read> Write for Port<P> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.get_mut().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.get_mut().flush()
    }
}
