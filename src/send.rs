// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    frame::{Frame, Header, Type},
    port, write_zdle_data, ZCRCG, ZCRCW, ZDATA_HEADER, ZEOF_HEADER, ZFILE_HEADER, ZFIN_HEADER,
    ZNAK_HEADER, ZRQINIT_HEADER,
};
use std::io::{Read, Result, Seek, SeekFrom, Write};

const SUBPACKET_SIZE: usize = 1024 * 8;
const SUBPACKET_PER_ACK: usize = 10;

/// Map the previous frame type of the sender and incoming frame type of the
/// receiver to the next packet to be sent.
///
/// NOTE: ZRINIT is used here as a wait state, as the sender does not use it for
/// other purposes. Other than tat the states map to the packets that the sender
/// sends next.
const fn next_state(sender: Option<Type>, receiver: Type) -> Option<Type> {
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
    let mut state = None;

    port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?;

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

        match state {
            Some(Type::ZRQINIT) => port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?,
            Some(Type::ZFILE) => write_zfile(&mut port, filename, filesize)?,
            Some(Type::ZDATA) => write_zdata(&mut port, r, &frame)?,
            Some(Type::ZFIN) => port.write_all(&Frame::new(&ZFIN_HEADER).0)?,
            None => {
                port.write_all("OO".as_bytes())?;
                break;
            }
            _ => (),
        }
    }

    Ok(())
}

/// Sends a ZFILE packet containing file's name and size.
fn write_zfile<P>(port: &mut P, name: &str, maybe_size: Option<u32>) -> Result<()>
where
    P: Read + Write,
{
    port.write_all(&Frame::new(&ZFILE_HEADER).0)?;

    let mut data = format!("{}\0", name);
    if let Some(size) = maybe_size {
        data += &format!(" {}", size);
    }
    data += "\0";

    write_zdle_data(port, ZCRCW, data.as_bytes())
}

/// Write a ZDATA packet from the given file offset in the ZBIN32 format.
fn write_zdata<P, F>(port: &mut P, file: &mut F, header: &Header) -> Result<()>
where
    P: Read + Write,
    F: Read + Seek,
{
    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32 = header.count();

    file.seek(SeekFrom::Start(offset as u64))?;

    let mut count = file.read(&mut data)?;

    if count == 0 {
        port.write_all(&Frame::new(&ZEOF_HEADER.with_count(offset)).0)?;
        return Ok(());
    }

    port.write_all(&Frame::new(&ZDATA_HEADER.with_count(offset)).0)?;

    for _ in 1..SUBPACKET_PER_ACK {
        write_zdle_data(port, ZCRCG, &data[..count])?;
        offset += count as u32;

        count = file.read(&mut data)?;
        if count < SUBPACKET_SIZE {
            break;
        }
    }

    write_zdle_data(port, ZCRCW, &data[..count])?;
    Ok(())
}
