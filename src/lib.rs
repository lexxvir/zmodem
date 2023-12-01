// SPDX-License-Identifier: MIT OR Apache-2.0

mod header;
mod port;
mod subpacket;

use core::convert::TryFrom;
use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};
use header::{Encoding, Header, Type};
use std::io::{self, BufRead, Read, Result, Seek, SeekFrom, Write};
use std::str::from_utf8;

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const ZACK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZACK);
pub const ZDATA_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZDATA);
pub const ZEOF_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZEOF);
pub const ZFILE_HEADER: Header =
    Header::new(Encoding::ZBIN32, Type::ZFILE).with_flags(&[0, 0, 0, 0x23]);
pub const ZFIN_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZFIN);
pub const ZNAK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZNAK);
pub const ZRINIT_HEADER: Header =
    Header::new(Encoding::ZHEX, Type::ZRINIT).with_flags(&[0, 0, 0, 0x23]);
pub const ZRPOS_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRPOS);
pub const ZRQINIT_HEADER: Header =
    Header::new(Encoding::ZHEX, Type::ZRQINIT).with_flags(&[0, 0, 0, 0x23]);

pub const ZPAD: u8 = b'*';
pub const ZDLE: u8 = 0x18;

pub const XON: u8 = 0x11;

pub const SUBPACKET_SIZE: usize = 1024 * 8;
pub const SUBPACKET_PER_ACK: usize = 10;

#[derive(PartialEq)]
enum Stage {
    Waiting,
    Ready,
    Receiving,
}

/// Sends a file using the ZMODEM file transfer protocol.
pub fn send<P, F>(port: &mut P, file: &mut F, filename: &str, filesize: Option<u32>) -> Result<()>
where
    P: Read + Write,
    F: Read + Seek,
{
    let mut stage = Stage::Waiting;
    let mut port = port::Port::new(port);

    ZRQINIT_HEADER.write(&mut port)?;
    loop {
        port.flush()?;
        if !skip_zpad(&mut port)? {
            continue;
        }
        let frame = match Header::read(&mut port)? {
            Some(x) => x,
            None => {
                ZNAK_HEADER.write(&mut port)?;
                continue;
            }
        };

        if stage == Stage::Waiting {
            if frame.frame_type() == Type::ZRINIT {
                write_zfile(&mut port, filename, filesize)?;
                stage = Stage::Ready;
            } else {
                ZRQINIT_HEADER.write(&mut port)?;
            }
        } else {
            match frame.frame_type() {
                Type::ZRPOS | Type::ZACK => {
                    write_zdata(&mut port, file, &frame)?;
                    stage = Stage::Receiving;
                }
                Type::ZRINIT => {
                    if stage == Stage::Receiving {
                        ZFIN_HEADER.write(&mut port)?;
                    }
                }
                _ => {
                    port.write_all("OO".as_bytes())?;
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Receives a file using the ZMODEM file transfer protocol.
pub fn recv<P, F>(port: &mut P, file: &mut F) -> Result<usize>
where
    P: Read + Write,
    F: Write,
{
    let mut stage = Stage::Waiting;
    let mut port = port::Port::new(port);
    let mut count = 0;

    ZRINIT_HEADER.write(&mut port)?;

    loop {
        if !skip_zpad(&mut port)? {
            continue;
        }

        let frame = match Header::read(&mut port)? {
            Some(frame) => frame,
            _ => {
                if stage == Stage::Receiving {
                    ZRPOS_HEADER.with_count(count).write(&mut port)?;
                } else {
                    ZNAK_HEADER.write(&mut port)?;
                }
                continue;
            }
        };

        match stage {
            Stage::Waiting => match frame.frame_type() {
                Type::ZFILE => {
                    read_zfile(frame.encoding(), &count, &mut port)?;
                    stage = Stage::Ready;
                }
                _ => {
                    ZRINIT_HEADER.write(&mut port)?;
                }
            },
            Stage::Ready => match frame.frame_type() {
                Type::ZFILE => read_zfile(frame.encoding(), &count, &mut port)?,
                Type::ZDATA => {
                    if frame.count() != count
                        || !read_zdata(frame.encoding() as u8, &mut count, &mut port, file)?
                    {
                        ZRPOS_HEADER.with_count(count).write(&mut port)?
                    }
                    stage = Stage::Receiving;
                }
                _ => (),
            },
            Stage::Receiving => match frame.frame_type() {
                Type::ZDATA => {
                    if frame.count() != count
                        || !read_zdata(frame.encoding() as u8, &mut count, &mut port, file)?
                    {
                        ZRPOS_HEADER.with_count(count).write(&mut port)?
                    }
                }
                Type::ZEOF => {
                    if frame.count() != count {
                        log::error!(
                            "ZEOF offset mismatch: frame({}) != recv({})",
                            frame.count(),
                            count
                        );
                    } else {
                        ZRINIT_HEADER.write(&mut port)?
                    }
                }
                Type::ZFIN => {
                    ZFIN_HEADER.write(&mut port)?;
                    break;
                }
                _ => (),
            },
        }
    }

    Ok(count as usize)
}

/// Sends a ZFILE packet containing file's name and size.
fn write_zfile<P>(port: &mut P, name: &str, maybe_size: Option<u32>) -> Result<()>
where
    P: Read + Write,
{
    let mut data = vec![];

    ZFILE_HEADER.write(port)?;
    data.extend_from_slice(name.as_bytes());
    data.push(b'\0');
    if let Some(size) = maybe_size {
        data.extend_from_slice(size.to_string().as_bytes());
    }
    data.push(b'\0');
    write_subpacket(port, Encoding::ZBIN32, subpacket::Type::ZCRCW, &data)
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
        ZEOF_HEADER.with_count(offset).write(port)?;
        return Ok(());
    }

    ZDATA_HEADER.with_count(offset).write(port)?;
    for _ in 1..SUBPACKET_PER_ACK {
        write_subpacket(
            port,
            Encoding::ZBIN32,
            subpacket::Type::ZCRCG,
            &data[..count],
        )?;
        offset += count as u32;

        count = file.read(&mut data)?;
        if count < SUBPACKET_SIZE {
            break;
        }
    }
    write_subpacket(
        port,
        Encoding::ZBIN32,
        subpacket::Type::ZCRCW,
        &data[..count],
    )?;

    Ok(())
}

fn read_zfile<P>(encoding: Encoding, count: &u32, port: &mut P) -> Result<()>
where
    P: Write + BufRead,
{
    let mut buf = Vec::new();

    if read_subpacket(port, encoding, &mut buf)?.is_none() {
        ZNAK_HEADER.write(port)?;
    } else {
        ZRPOS_HEADER.with_count(*count).write(port)?;

        // TODO: Process supplied data.
        if let Ok(s) = from_utf8(&buf) {
            log::debug!(target: "proto", "ZFILE supplied data: {}", s);
        }
    }

    Ok(())
}

fn read_zdata<P, F>(encoding: u8, count: &mut u32, port: &mut P, file: &mut F) -> Result<bool>
where
    P: Write + BufRead,
    F: Write,
{
    let mut buf = Vec::new();

    loop {
        buf.clear();

        let encoding = match encoding.try_into() {
            Ok(encoding) => encoding,
            Err(_) => return Ok(false),
        };

        let zcrc = match read_subpacket(port, encoding, &mut buf)? {
            Some(x) => x,
            None => return Ok(false),
        };

        file.write_all(&buf)?;
        *count += buf.len() as u32;

        match zcrc {
            subpacket::Type::ZCRCW => {
                ZACK_HEADER.with_count(*count).write(port)?;
                return Ok(true);
            }
            subpacket::Type::ZCRCE => return Ok(true),
            subpacket::Type::ZCRCQ => {
                ZACK_HEADER.with_count(*count).write(port)?;
            }
            subpacket::Type::ZCRCG => log::debug!("ZCRCG"),
        }
    }
}

pub const fn escape(value: u8) -> u8 {
    match value {
        0xff => 0x6d,
        0x7f => 0x6c,
        0x10 | 0x90 | 0x11 | 0x91 | 0x13 | 0x93 | ZDLE => value ^ 0x40,
        // Telenet command escaping, which actually necessary only when preceded
        // by 0x40 or 0xc0, meaning that this could be optimized a bit with the
        // help of previous byte.
        0x0d | 0x8d => value ^ 0x40,
        _ => value,
    }
}

pub const fn unescape(value: u8) -> u8 {
    match value {
        0x6d => 0xff,
        0x6c => 0x7f,
        _ => {
            // Bit 6 must be set and bit 5 *reset*:
            if value & 0x60 == 0x40 {
                value ^ 0x40
            } else {
                value
            }
        }
    }
}

pub fn escape_array(src: &[u8], dst: &mut Vec<u8>) {
    for value in src {
        let escaped = escape(*value);
        if escaped != *value {
            dst.push(ZDLE);
        }
        dst.push(escaped);
    }
}

/// Skips (ZPAD, [ZPAD,] ZDLE) sequence.
fn skip_zpad<P>(port: &mut P) -> io::Result<bool>
where
    P: BufRead,
{
    let mut buf = [0; 1];

    let mut value = port.read_exact(&mut buf).map(|_| buf[0])?;
    if value != ZPAD {
        return Ok(false);
    }

    value = port.read_exact(&mut buf).map(|_| buf[0])?;
    if value == ZPAD {
        value = port.read_exact(&mut buf).map(|_| buf[0])?;
    }

    Ok(value == ZDLE)
}

/// Reads and unescapes a ZMODEM protocol subpacket
fn read_subpacket<P>(
    port: &mut P,
    encoding: Encoding,
    buf: &mut Vec<u8>,
) -> io::Result<Option<subpacket::Type>>
where
    P: BufRead,
{
    let result;

    loop {
        // FIXME: To be aligned with the ZMODEM specification 0x11, 0x91, 0x13
        // and 0x93 should be ignored here.
        port.read_until(ZDLE, buf)?;

        let mut byte = [0; 1];
        let byte = port.read_exact(&mut byte).map(|_| byte[0])?;

        if let Ok(sp_type) = subpacket::Type::try_from(byte) {
            *buf.last_mut().unwrap() = sp_type as u8;
            result = Some(sp_type);
            break;
        } else {
            *buf.last_mut().unwrap() = unescape(byte);
        }
    }

    let crc_len = if encoding == Encoding::ZBIN32 { 4 } else { 2 };
    let mut crc1 = vec![0; crc_len];

    read_exact_unescaped(port, &mut crc1)?;

    let crc2 = match encoding {
        Encoding::ZBIN32 => CRC32.checksum(buf).to_le_bytes().to_vec(),
        _ => CRC16.checksum(buf).to_be_bytes().to_vec(),
    };

    if crc1 != crc2 {
        log::debug!("CRC mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    // Pop ZCRC
    buf.pop().unwrap();

    Ok(result)
}

fn read_exact_unescaped<R>(mut r: R, buf: &mut [u8]) -> io::Result<()>
where
    R: io::Read,
{
    for x in buf {
        let mut buf = [0; 1];

        *x = match r.read_exact(&mut buf).map(|_| buf[0])? {
            ZDLE => unescape(r.read_exact(&mut buf).map(|_| buf[0])?),
            y => y,
        };
    }

    Ok(())
}

fn write_subpacket<P>(
    port: &mut P,
    encoding: Encoding,
    subpacket_type: subpacket::Type,
    data: &[u8],
) -> Result<()>
where
    P: Write,
{
    let subpacket_type = subpacket_type as u8;

    let mut esc_data = vec![];
    escape_array(data, &mut esc_data);
    port.write_all(&esc_data)?;

    let mut esc_crc = vec![];

    match encoding {
        Encoding::ZBIN32 => {
            let mut digest = CRC32.digest();
            digest.update(data);
            digest.update(&[subpacket_type]);
            escape_array(&digest.finalize().to_le_bytes(), &mut esc_crc)
        }
        Encoding::ZBIN => {
            let mut digest = CRC16.digest();
            digest.update(data);
            digest.update(&[subpacket_type]);
            escape_array(&digest.finalize().to_be_bytes(), &mut esc_crc)
        }
        Encoding::ZHEX => {
            unimplemented!()
        }
    };

    port.write_all(&[ZDLE, subpacket_type])?;
    port.write_all(&esc_crc)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        header::{Encoding, Header, Type},
        read_subpacket, skip_zpad, subpacket, write_subpacket, XON, ZDLE, ZPAD,
    };

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(Encoding::ZBIN32, Type::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN32 as u8, 0, 0, 0, 0, 0, 29, 247, 34, 198])]
    pub fn test_header(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type).with_flags(&[0; 4]);
        let mut port = vec![];
        header.write(&mut port).unwrap();
        assert_eq!(port, expected);
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZDLE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148])]
    #[case(Encoding::ZHEX, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZPAD, ZDLE, Encoding::ZHEX as u8, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'1', b'0', b'1', 54, 50, 57, 52, b'\r', b'\n', XON])]
    pub fn test_header_with_flags(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] flags: &[u8; 4],
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type).with_flags(flags);
        let mut port = vec![];
        header.write(&mut port).unwrap();
        assert_eq!(port, expected);
    }

    #[rstest::rstest]
    #[case(&[ZPAD, ZDLE], Ok(true))]
    #[case(&[ZPAD, ZPAD, ZDLE], Ok(true))]
    #[case(&[ZDLE], Ok(true))]
    #[case(&[], Err(std::io::ErrorKind::InvalidData.into()))]
    #[case(&[0; 100], Ok(false))]
    pub fn test_skip_zpad(#[case] data: &[u8], #[case] expected: std::io::Result<bool>) {
        let data = data.to_vec();
        assert_eq!(skip_zpad(&mut data.as_slice()).is_err(), expected.is_err());
    }

    #[rstest::rstest]
    #[case(&[Encoding::ZHEX as u8, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'], &Header::new(Encoding::ZHEX, Type::ZRINIT).with_flags(&[0x1, 0x2, 0x3, 0x4]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb], &Header::new(Encoding::ZBIN, Type::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN32 as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a], &Header::new(Encoding::ZBIN32, Type::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, ZDLE, b'l', 0xd, ZDLE, b'm', 0x5e, 0x6f], &Header::new(Encoding::ZBIN, Type::ZRINIT).with_flags(&[0xa, 0x7f, 0xd, 0xff]))]
    pub fn test_header_read(#[case] input: &[u8], #[case] expected: &Header) {
        assert_eq!(&mut Header::read(&input[..]).unwrap().unwrap(), expected);
    }

    #[test]
    fn test_parse_header_none() {
        let frame = Type::ZRINIT;
        let i = [0xaa, frame as u8, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf];
        assert_eq!(Header::read(&i[..]).unwrap_or(None), None);
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, subpacket::Type::ZCRCE, &[])]
    #[case(Encoding::ZBIN, subpacket::Type::ZCRCW, &[0x00])]
    #[case(Encoding::ZBIN32, subpacket::Type::ZCRCQ, &[0, 1, 2, 3, 4, 0x60, 0x60])]
    pub fn test_write_read_subpacket(
        #[case] encoding: Encoding,
        #[case] subpacket_type: subpacket::Type,
        #[case] data: &[u8],
    ) {
        let mut port = vec![];
        let mut output = vec![];

        write_subpacket(&mut port, encoding, subpacket_type, data).unwrap();
        assert_eq!(
            read_subpacket(&mut port.as_slice(), encoding, &mut output).unwrap(),
            Some(subpacket_type)
        );

        assert_eq!(&output[..], data);
    }
}
