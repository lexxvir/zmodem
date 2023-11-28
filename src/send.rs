// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Result, Seek, SeekFrom, Write};

use crate::frame::*;
use crate::port;
use crate::*;

const SUBPACKET_SIZE: usize = 1024 * 8;
const SUBPACKET_PER_ACK: usize = 10;

#[derive(Debug, PartialEq)]
enum State {
    /// Waiting ZRINIT invite (do nothing)
    WaitingInit,

    /// Sending ZRQINIT
    SendingZRQINIT,

    /// Sending ZFILE frame
    SendingZFILE,

    /// Do nothing, just waiting for ZPOS
    WaitingZPOS,

    /// Sending ZDATA & subpackets
    SendingData,

    /// Sending ZFIN
    SendingZFIN,

    /// All works done, exiting
    Done,
}

impl State {
    fn new() -> State {
        State::WaitingInit
    }

    fn next(self, frame: &Header) -> State {
        match (self, frame.frame_type()) {
            (State::WaitingInit, Type::ZRINIT) => State::SendingZFILE,
            (State::WaitingInit, _) => State::SendingZRQINIT,

            (State::SendingZRQINIT, Type::ZRINIT) => State::SendingZFILE,

            (State::SendingZFILE, Type::ZRPOS) => State::SendingData,
            (State::SendingZFILE, Type::ZRINIT) => State::WaitingZPOS,

            (State::WaitingZPOS, Type::ZRPOS) => State::SendingData,

            (State::SendingData, Type::ZACK) => State::SendingData,
            (State::SendingData, Type::ZRPOS) => State::SendingData,
            (State::SendingData, Type::ZRINIT) => State::SendingZFIN,

            (State::SendingZFIN, Type::ZFIN) => State::Done,

            (s, _) => {
                error!("Unexpected (state, frame) combination: {:#?} {}", s, frame);
                s // don't change current state
            }
        }
    }
}

/// Sends a file using the ZMODEM file transfer protocol.
pub fn send<RW, R>(rw: RW, r: &mut R, filename: &str, filesize: Option<u32>) -> Result<()>
where
    RW: Read + Write,
    R: Read + Seek,
{
    let mut port = port::Port::new(rw);

    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32;

    port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?;

    let mut state = State::new();

    while state != State::Done {
        port.flush()?;

        if !crate::try_skip_zpad(&mut port)? {
            continue;
        }

        let frame = match crate::parse_header(&mut port)? {
            Some(x) => x,
            None => {
                port.write_all(&Frame::new(&ZNAK_HEADER).0)?;
                continue;
            }
        };

        state = state.next(&frame);
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            State::SendingZRQINIT => port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?,
            State::SendingZFILE => {
                port.write_all(&Frame::new(&ZFILE_HEADER).0)?;
                let mut zfile_data = format!("{}\0", filename);
                if let Some(size) = filesize {
                    zfile_data += &format!(" {}", size);
                }
                zfile_data += "\0";
                crate::write_zlde_data(&mut port, ZCRCW, zfile_data.as_bytes())?;
            }
            State::SendingData => {
                offset = frame.count();
                r.seek(SeekFrom::Start(offset as u64))?;

                let num = r.read(&mut data)?;

                if num == 0 {
                    port.write_all(&Frame::new(&ZEOF_HEADER.with_count(offset)).0)?;
                } else {
                    // ZBIN32|ZDATA
                    // ZCRCG - best perf
                    // ZCRCQ - mid perf
                    // ZCRCW - worst perf
                    // ZCRCE - send at end
                    port.write_all(&Frame::new(&ZDATA_HEADER.with_count(offset)).0)?;

                    let mut i = 0;
                    loop {
                        i += 1;

                        crate::write_zlde_data(&mut port, ZCRCG, &data[..num])?;
                        offset += num as u32;

                        let num = r.read(&mut data)?;
                        if num < data.len() || i >= SUBPACKET_PER_ACK {
                            crate::write_zlde_data(&mut port, ZCRCW, &data[..num])?;
                            break;
                        }
                    }
                }
            }
            State::SendingZFIN => port.write_all(&Frame::new(&ZFIN_HEADER).0)?,
            // Write "over and out" (OO):
            State::Done => port.write_all("OO".as_bytes())?,
            _ => (),
        }
    }

    Ok(())
}
