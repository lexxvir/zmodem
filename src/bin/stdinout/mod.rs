use std::io::*;

pub struct CombinedStdInOut {
    stdin:  Stdin,
    stdout: Stdout,
}

impl CombinedStdInOut {
    pub fn new() -> CombinedStdInOut {
        CombinedStdInOut {
            stdin:  stdin(),
            stdout: stdout(),
        }
    }
}

impl Read for CombinedStdInOut {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stdin.read(buf)
    }
}

impl Write for CombinedStdInOut {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let r = self.stdout.write(buf)?;
        self.stdout.flush()?;
        Ok(r)
    }

    fn flush(&mut self) -> Result<()> {
        self.stdout.flush()
    }
}
