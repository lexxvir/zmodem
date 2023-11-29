extern crate zmodem;

extern crate clap;
extern crate env_logger;
extern crate log;

mod stdinout;

use clap::{App, Arg};
use std::fs::File;
use std::path::Path;

fn main() {
    env_logger::init().unwrap();

    let matches = App::new("Pure Rust implementation of sz utility")
        .arg(Arg::with_name("file").required(true).index(1))
        .get_matches();

    let fileopt = matches.value_of("file").unwrap();
    let mut file = File::open(fileopt).unwrap();

    let filename = Path::new(fileopt).file_name().unwrap();
    let size = file.metadata().map(|x| x.len() as u32).ok();

    let inout = stdinout::CombinedStdInOut::new();

    zmodem::send(inout, &mut file, filename.to_str().unwrap(), size).unwrap();
}
