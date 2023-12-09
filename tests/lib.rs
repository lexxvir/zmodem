extern crate zmodem2;

use std::fs::{remove_file, File, OpenOptions};
use std::io::*;
use std::process::*;
use std::thread::spawn;

struct InOut<R: Read, W: Write> {
    r: R,
    w: W,
}

impl<R: Read, W: Write> InOut<R, W> {
    pub fn new(r: R, w: W) -> InOut<R, W> {
        InOut { r, w }
    }
}

impl<R: Read, W: Write> Read for InOut<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.r.read(buf)
    }
}

impl<R: Read, W: Write> Write for InOut<R, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.w.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.w.flush()
    }
}

const TEST_DATA: &[u8] = include_bytes!("test.bin");
const TMP_DIR: &str = env!("CARGO_TARGET_TMPDIR");

#[test]
#[cfg(unix)]
fn test_from_sz() {
    let file_name = format!("{TMP_DIR}/from_sz.bin");
    let mut file = File::create(&file_name).unwrap();
    file.write_all(&TEST_DATA).unwrap();
    let sz = Command::new("sz")
        .arg(&file_name)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = sz.stdin.unwrap();
    let stdout = sz.stdout.unwrap();
    let mut port = InOut::new(stdout, stdin);
    let mut file = Cursor::new(Vec::new());
    let mut state = zmodem2::State::new();
    while state.stage() != zmodem2::Stage::Done {
        assert!(zmodem2::receive(&mut port, &mut file, &mut state) == Ok(()));
    }
    assert_eq!(TEST_DATA, file.into_inner());
}

#[test]
#[cfg(unix)]
fn test_to_rz() {
    let file_name = format!("{TMP_DIR}/to_rz.bin");
    remove_file(&file_name).unwrap_or_default();
    let sz = Command::new("rz")
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = sz.stdin.unwrap();
    let stdout = sz.stdout.unwrap();
    let mut port = InOut::new(stdout, stdin);
    let len = TEST_DATA.len() as u32;
    let mut file = Cursor::new(TEST_DATA);
    let mut state = zmodem2::State::new();
    while state.stage() != zmodem2::Stage::Done {
        assert!(zmodem2::send(&mut port, &mut file, &mut state, &file_name, len) == Ok(()));
    }
    let mut f = File::open(&file_name).unwrap();
    let mut received = Vec::new();
    f.read_to_end(&mut received).unwrap();
    assert!(TEST_DATA == received);
}

#[test]
#[cfg(unix)]
fn lib_send_recv() {
    let _ = remove_file("test-fifo1");
    let _ = remove_file("test-fifo2");

    let _ = Command::new("mkfifo")
        .arg("test-fifo1")
        .spawn()
        .expect("mkfifo failed to run")
        .wait();

    let _ = Command::new("mkfifo")
        .arg("test-fifo2")
        .spawn()
        .expect("mkfifo failed to run")
        .wait();

    spawn(move || {
        let outf = OpenOptions::new().write(true).open("test-fifo1").unwrap();
        let inf = File::open("test-fifo2").unwrap();
        let mut port = InOut::new(inf, outf);
        let mut file = Cursor::new(TEST_DATA);
        let mut state = zmodem2::State::new();
        while state.stage() != zmodem2::Stage::Done {
            assert!(
                zmodem2::send(
                    &mut port,
                    &mut file,
                    &mut state,
                    "test",
                    TEST_DATA.len() as u32
                ) == Ok(())
            );
        }
    });

    let mut file = Cursor::new(Vec::new());

    let inf = File::open("test-fifo1").unwrap();
    let outf = OpenOptions::new().write(true).open("test-fifo2").unwrap();
    let mut port = InOut::new(inf, outf);

    let mut state = zmodem2::State::new();
    while state.stage() != zmodem2::Stage::Done {
        assert!(zmodem2::receive(&mut port, &mut file, &mut state) == Ok(()));
    }

    let _ = remove_file("test-fifo1");
    let _ = remove_file("test-fifo2");

    assert_eq!(TEST_DATA, file.into_inner());
}
