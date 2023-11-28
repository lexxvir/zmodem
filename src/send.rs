// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Result, Seek, SeekFrom, Write};

use crate::frame::*;
use crate::port;
use crate::*;

const SUBPACKET_SIZE: usize = 1024 * 8;
const SUBPACKET_PER_ACK: usize = 10;

fn next_state(sender: Option<Type>, receiver: Type) -> Option<Type> {
    match (sender, receiver) {
        (None, Type::ZRINIT) => Some(Type::ZFILE),
        (None, _) => Some(Type::ZRQINIT),
        (Some(Type::ZRQINIT), Type::ZRINIT) => Some(Type::ZFILE),
        (Some(Type::ZFILE), Type::ZRPOS) => Some(Type::ZDATA),
        (Some(Type::ZFILE), Type::ZRINIT) => Some(Type::ZRINIT),
        (Some(Type::ZRINIT), Type::ZRPOS) => Some(Type::ZDATA),
        (Some(Type::ZDATA), Type::ZACK) => Some(Type::ZDATA),
        (Some(Type::ZDATA), Type::ZRPOS) => Some(Type::ZDATA),
        (Some(Type::ZDATA), Type::ZRINIT) => Some(Type::ZFIN),
        (Some(Type::ZFIN), Type::ZFIN) => None,
        (_, _) => None,
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

    let mut state = None;

    loop {
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

        state = next_state(state, frame.frame_type());
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            Some(Type::ZRQINIT) => port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?,
            Some(Type::ZFILE) => {
                port.write_all(&Frame::new(&ZFILE_HEADER).0)?;
                let mut zfile_data = format!("{}\0", filename);
                if let Some(size) = filesize {
                    zfile_data += &format!(" {}", size);
                }
                zfile_data += "\0";
                crate::write_zlde_data(&mut port, ZCRCW, zfile_data.as_bytes())?;
            }
            Some(Type::ZDATA) => {
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
            Some(Type::ZFIN) => port.write_all(&Frame::new(&ZFIN_HEADER).0)?,
            // Write "over and out" (OO):
            None => {
                port.write_all("OO".as_bytes())?;
                break;
            }
            _ => (),
        }
    }

    Ok(())
}
