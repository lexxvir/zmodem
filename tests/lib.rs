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

#[test]
#[cfg(unix)]
fn recv_from_sz() {
    let mut f = File::create("recv_from_sz").unwrap();
    f.write_all(&TEST_DATA).unwrap();

    let sz = Command::new("sz")
        .arg("recv_from_sz")
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .expect("sz failed to run");

    let child_stdin = sz.stdin.unwrap();
    let child_stdout = sz.stdout.unwrap();
    let mut port = InOut::new(child_stdout, child_stdin);
    let mut file = Cursor::new(Vec::new());
    let mut state = zmodem2::State::new();

    while state.stage() != zmodem2::Stage::Done {
        assert!(zmodem2::receive(&mut port, &mut file, &mut state) == Ok(()));
    }

    remove_file("recv_from_sz").unwrap();

    assert_eq!(TEST_DATA, file.into_inner());
}

#[test]
#[cfg(unix)]
fn send_to_rz() {
    let _ = remove_file("send_to_rz");

    let sz = Command::new("rz")
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .expect("rz failed to run");

    let child_stdin = sz.stdin.unwrap();
    let child_stdout = sz.stdout.unwrap();
    let mut port = InOut::new(child_stdout, child_stdin);

    let len = TEST_DATA.len() as u32;
    let copy = TEST_DATA;
    let mut file = Cursor::new(&copy);
    let mut state = zmodem2::State::new();

    while state.stage() != zmodem2::Stage::Done {
        assert!(zmodem2::send(&mut port, &mut file, &mut state, "send_to_rz", len) == Ok(()));
    }


    let mut f = File::open("send_to_rz").expect("open 'send_to_rz'");
    let mut received = Vec::new();
    f.read_to_end(&mut received).unwrap();
    remove_file("send_to_rz").unwrap();

    assert!(copy == received);
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
