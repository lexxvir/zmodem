extern crate zmodem;

extern crate log;
extern crate env_logger;
extern crate clap;

mod stdinout;

use std::fs::File;
use std::path::Path;
use clap::{Arg, App};

fn main() {
    env_logger::init().unwrap();

    let matches = App::new("Pure Rust implementation of sz utility")
        .arg(Arg::with_name("file")
             .required(true)
             .index(1))
        .get_matches();

    let fileopt = matches.value_of("file").unwrap();
    let mut file = File::open(fileopt).unwrap();

    let filename = Path::new(fileopt).file_name().unwrap().clone();
    let size = file.metadata().map(|x| x.len() as u32).ok();

    let inout = stdinout::CombinedStdInOut::new();

    zmodem::send::send(inout, &mut file, filename.to_str().unwrap(), size).unwrap();
}
