// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Result, Seek, SeekFrom, Write};

use crate::consts::*;
use crate::frame::*;
use crate::port;
use log::LogLevel::Debug;

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
                write_zlde_data(&mut port, ZCRCW, zfile_data.as_bytes())?;
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
            State::SendingZFIN => port.write_all(&Frame::new(&ZFIN_HEADER).0)?,
            // Write "over and out" (OO):
            State::Done => port.write_all("OO".as_bytes())?,
            _ => (),
        }
    }

    Ok(())
}

fn write_zlde_data<W>(w: &mut W, zcrc_byte: u8, data: &[u8]) -> Result<()>
where
    W: Write,
{
    if log_enabled!(Debug) {
        debug!(
            "  ZCRC{} subpacket, size = {}",
            match zcrc_byte {
                ZCRCE => "E",
                ZCRCG => "G",
                ZCRCQ => "Q",
                ZCRCW => "W",
                _ => "?",
            },
            data.len()
        );
    }

    let mut digest = CRC32.digest();
    digest.update(data);
    digest.update(&[zcrc_byte]);
    // Assuming little-endian byte order, given that ZMODEM used to work on
    // VAX, which was a little-endian computer architecture:
    let crc = digest.finalize().to_le_bytes();

    write_escape(w, data)?;
    w.write_all(&[ZLDE, zcrc_byte])?;
    write_escape(w, &crc)?;

    Ok(())
}

fn write_escape<W>(w: &mut W, data: &[u8]) -> Result<()>
where
    W: Write,
{
    let mut esc_data = Vec::with_capacity(data.len() + data.len() / 10);
    crate::escape_array(data, &mut esc_data);
    w.write_all(&esc_data)
}
