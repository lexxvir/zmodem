use std::io::{Read, Result, Write};
use std::str::from_utf8;
use std::{thread, time};

use crate::consts::*;
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

/// Receives a file using the ZMODEM file transfer protocol.
pub fn recv<RW, W>(rw: RW, mut w: W) -> Result<usize>
where
    RW: Read + Write,
    W: Write,
{
    let mut port = port::Port::new(rw);
    let mut count = 0;

    let mut state = State::new();

    port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;

    while state != State::Done {
        if !try_skip_zpad(&mut port)? {
            continue;
        }

        let frame = match parse_header(&mut port)? {
            Some(x) => x,
            None => {
                match state {
                    State::ReceivingData => {
                        port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?
                    }
                    _ => port.write_all(&Frame::new(&ZNAK_HEADER).0)?,
                }
                continue;
            }
        };

        state = state.next(&frame);
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            State::SendingZRINIT => {
                port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;
            }
            State::ProcessingZFILE => {
                let mut buf = Vec::new();

                if recv_zlde_frame(frame.encoding(), &mut port, &mut buf)?.is_none() {
                    port.write_all(&Frame::new(&ZNAK_HEADER).0)?;
                } else {
                    port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?;

                    // TODO: process supplied data
                    if let Ok(s) = from_utf8(&buf) {
                        debug!(target: "proto", "ZFILE supplied data: {}", s);
                    }
                }
            }
            State::ReceivingData => {
                if frame.count() != count
                    || !recv_data(frame.encoding() as u8, &mut count, &mut port, &mut w)?
                {
                    port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?
                }
            }
            State::CheckingData => {
                if frame.count() != count {
                    error!(
                        "ZEOF offset mismatch: frame({}) != recv({})",
                        frame.count(),
                        count
                    );
                    // receiver ignores the ZEOF because a new zdata is coming
                } else {
                    port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;
                }
            }
            State::Done => {
                port.write_all(&Frame::new(&ZFIN_HEADER).0)?;
                thread::sleep(time::Duration::from_millis(10)); // sleep a bit
            }
        }
    }

    Ok(count as usize)
}
