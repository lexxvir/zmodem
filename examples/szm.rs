extern crate clap;
extern crate zmodem;

mod stdinout;

use clap::{App, Arg};
use std::fs::File;
use std::path::Path;

fn main() {
    let matches = App::new("Pure Rust implementation of sz utility")
        .arg(Arg::with_name("file").required(true).index(1))
        .get_matches();

    let fileopt = matches.value_of("file").unwrap();
    let mut file = File::open(fileopt).unwrap();
    let filename = Path::new(fileopt).file_name().unwrap();
    let size = file.metadata().map(|x| x.len() as u32).ok();
    let mut port = stdinout::CombinedStdInOut::new();
    let mut state = zmodem::State::new();

    assert!(
        zmodem::write(
            &mut port,
            &mut file,
            &mut state,
            filename.to_str().unwrap(),
            size
        ) == Ok(())
    );
}
