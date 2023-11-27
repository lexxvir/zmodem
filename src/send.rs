// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Result, Seek, SeekFrom, Write};

use crate::consts::*;
use crate::frame::*;
use crate::port;
use crate::proto::*;

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

pub fn send<RW, R>(rw: RW, r: &mut R, filename: &str, filesize: Option<u32>) -> Result<()>
where
    RW: Read + Write,
    R: Read + Seek,
{
    let mut port = port::Port::new(rw);

    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32;

    write_zrqinit(&mut port)?;

    let mut state = State::new();

    while state != State::Done {
        port.flush()?;

        if !try_skip_zpad(&mut port)? {
            continue;
        }

        let frame = match parse_header(&mut port)? {
            Some(x) => x,
            None => {
                write_znak(&mut port)?;
                continue;
            }
        };

        state = state.next(&frame);
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            State::SendingZRQINIT => {
                write_zrqinit(&mut port)?;
            }
            State::SendingZFILE => {
                write_zfile(&mut port, filename, filesize)?;
            }
            State::SendingData => {
                offset = frame.get_count();
                r.seek(SeekFrom::Start(offset as u64))?;

                let num = r.read(&mut data)?;

                if num == 0 {
                    write_zeof(&mut port, offset)?;
                } else {
                    // ZBIN32|ZDATA
                    // ZCRCG - best perf
                    // ZCRCQ - mid perf
                    // ZCRCW - worst perf
                    // ZCRCE - send at end
                    write_zdata(&mut port, offset)?;

                    let mut i = 0;
                    loop {
                        i += 1;

                        write_zlde_data(&mut port, ZCRCG, &data[..num])?;
                        offset += num as u32;

                        let num = r.read(&mut data)?;
                        if num < data.len() || i >= SUBPACKET_PER_ACK {
                            write_zlde_data(&mut port, ZCRCW, &data[..num])?;
                            break;
                        }
                    }
                }
            }
            State::SendingZFIN => {
                write_zfin(&mut port)?;
            }
            State::Done => {
                write_over_and_out(&mut port)?;
            }
            _ => (),
        }
    }

    Ok(())
}
