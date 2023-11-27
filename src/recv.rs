use std::io::{Read, Result, Write};
use std::str::from_utf8;
use std::{thread, time};

use crate::frame::*;
use crate::port;
use crate::proto::*;

#[derive(Debug, PartialEq)]
enum State {
    /// Sending ZRINIT
    SendingZRINIT,

    /// Processing ZFILE supplementary data
    ProcessingZFILE,

    /// Receiving file's content
    ReceivingData,

    /// Checking length of received data
    CheckingData,

    /// All works done, exiting
    Done,
}

impl State {
    fn new() -> State {
        State::SendingZRINIT
    }

    fn next(self, frame: &Header) -> State {
        match (self, frame.frame_type()) {
            (State::SendingZRINIT, Type::ZFILE) => State::ProcessingZFILE,
            (State::SendingZRINIT, _) => State::SendingZRINIT,

            (State::ProcessingZFILE, Type::ZDATA) => State::ReceivingData,
            (State::ProcessingZFILE, _) => State::ProcessingZFILE,

            (State::ReceivingData, Type::ZDATA) => State::ReceivingData,
            (State::ReceivingData, Type::ZEOF) => State::CheckingData,

            (State::CheckingData, Type::ZDATA) => State::ReceivingData,
            (State::CheckingData, Type::ZFIN) => State::Done,

            (s, _) => {
                error!("Unexpected (state, frame) combination: {:#?} {}", s, frame);
                s // don't change current state
            }
        }
    }
}

/// Receives data by Z-Modem protocol
pub fn recv<RW, W>(rw: RW, mut w: W) -> Result<usize>
where
    RW: Read + Write,
    W: Write,
{
    let mut port = port::Port::new(rw);
    let mut count = 0;

    let mut state = State::new();

    write_zrinit(&mut port)?;

    while state != State::Done {
        if !find_zpad(&mut port)? {
            continue;
        }

        let frame = match parse_header(&mut port)? {
            Some(x) => x,
            None => {
                recv_error(&mut port, &state, count)?;
                continue;
            }
        };

        state = state.next(&frame);
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            State::SendingZRINIT => {
                write_zrinit(&mut port)?;
            }
            State::ProcessingZFILE => {
                let mut buf = Vec::new();

                if recv_zlde_frame(frame.encoding(), &mut port, &mut buf)?.is_none() {
                    write_znak(&mut port)?;
                } else {
                    write_zrpos(&mut port, count)?;

                    // TODO: process supplied data
                    if let Ok(s) = from_utf8(&buf) {
                        debug!(target: "proto", "ZFILE supplied data: {}", s);
                    }
                }
            }
            State::ReceivingData => {
                if frame.get_count() != count
                    || !recv_data(frame.encoding() as u8, &mut count, &mut port, &mut w)?
                {
                    write_zrpos(&mut port, count)?;
                }
            }
            State::CheckingData => {
                if frame.get_count() != count {
                    error!(
                        "ZEOF offset mismatch: frame({}) != recv({})",
                        frame.get_count(),
                        count
                    );
                    // receiver ignores the ZEOF because a new zdata is coming
                } else {
                    write_zrinit(&mut port)?;
                }
            }
            State::Done => {
                write_zfin(&mut port)?;
                thread::sleep(time::Duration::from_millis(10)); // sleep a bit
            }
        }
    }

    Ok(count as usize)
}

fn recv_error<W>(w: &mut W, state: &State, count: u32) -> Result<()>
where
    W: Write,
{
    // TODO: flush input

    match *state {
        State::ReceivingData => write_zrpos(w, count),
        _ => write_znak(w),
    }
}
