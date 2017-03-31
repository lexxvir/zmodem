extern crate zmodem;

extern crate log;
extern crate env_logger;
extern crate clap;

//mod stdinout;

use std::fs::File;
use std::path::Path;
use clap::{Arg, App};

use std::os::unix::io::FromRawFd;

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

    let mut stdin = unsafe { File::from_raw_fd(0) };
    let mut stdout = unsafe { File::from_raw_fd(1) };

    zmodem::send::send2(&mut stdin, &mut stdout, &mut file, filename.to_str().unwrap(), size);
}
