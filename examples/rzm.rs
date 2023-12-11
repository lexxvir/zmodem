extern crate clap;
extern crate zmodem2;

mod stdinout;

use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "Receive a ZMODEM file transfer", long_about = None)]
pub struct Arguments {
    /// Filename
    #[arg(short, long, default_value_t = String::default())]
    pub file_name: String,
}

fn main() {
    let mut port = stdinout::CombinedStdInOut::new();
    let mut state = zmodem2::State::new();
    let args = Arguments::parse();
    let mut buf = vec![];
    while state.stage() != zmodem2::Stage::InProgress {
        match zmodem2::receive(&mut port, &mut buf, &mut state) {
            Ok(()) => continue,
            _ => {
                eprintln!("RX error");
                return;
            }
        }
    }
    let file_name = if args.file_name.is_empty() {
        Path::new(state.file_name()).file_name().unwrap()
    } else {
        Path::new(&args.file_name).file_name().unwrap()
    };
    eprintln!(
        "RX {} {} bytes",
        file_name.to_str().unwrap(),
        state.file_size()
    );
    let mut file = File::create(file_name).unwrap();
    file.write_all(&buf).unwrap();
    while state.stage() != zmodem2::Stage::Done {
        match zmodem2::receive(&mut port, &mut file, &mut state) {
            Ok(()) => {
                eprintln!("RX {} / {}", state.count(), state.file_size());
                continue;
            }
            _ => {
                eprintln!("RX error");
                return;
            }
        }
    }
}
