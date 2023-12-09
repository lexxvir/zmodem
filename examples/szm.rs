extern crate clap;
extern crate zmodem2;

mod stdinout;

use clap::Parser;
use std::fs::File;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "Receive a ZMODEM file transfer", long_about = None)]
pub struct Arguments {
    /// Filename
    #[arg(short, long)]
    pub file_name: String,
}

fn main() {
    let args = Arguments::parse();
    let mut file = File::open(&args.file_name).unwrap();
    let filename = Path::new(&args.file_name).file_name().unwrap();
    let size = file.metadata().map(|x| x.len() as u32).unwrap();
    let mut port = stdinout::CombinedStdInOut::new();
    let mut state = zmodem2::State::new();
    while state.stage() != zmodem2::Stage::Done {
        assert!(
            zmodem2::send(
                &mut port,
                &mut file,
                &mut state,
                filename.to_str().unwrap(),
                size
            ) == Ok(())
        );
    }
}
