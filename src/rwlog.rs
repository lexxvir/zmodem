use std::io::*;
use log::LogLevel::*;
use hexdump::*;

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

        if log_enabled!(Debug) {
            debug!("In:");
            for x in hexdump_iter(&buf[..r]) {
                debug!("{}", x);
            }
        }

        Ok(r)
    }
}

impl<R: Read> BufRead for ReadWriteLog<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let r = self.inner.fill_buf()?;

        if log_enabled!(Debug) {
            debug!("In:");
            for x in hexdump_iter(r) {
                debug!("{}", x);
            }
        }

        Ok(r)
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

impl<RW: Write + Read> Write for ReadWriteLog<RW> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if log_enabled!(Debug) {
            debug!("Out:");
            for x in hexdump_iter(buf) {
                debug!("{}", x);
            }
        }

        self.inner.get_mut().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.get_mut().flush()
    }
}

