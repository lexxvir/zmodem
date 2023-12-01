// SPDX-License-Identifier: MIT OR Apache-2.0

mod header;
mod port;
mod subpacket;

use core::convert::TryFrom;
use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};
use header::{Encoding, Header, Type};
use std::io::{self, ErrorKind, Read, Result, Seek, SeekFrom, Write};

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
pub fn write<P, F>(port: &mut P, file: &mut F, filename: &str, filesize: Option<u32>) -> Result<()>
where
    P: Read + Write,
    F: Read + Seek,
{
    let mut stage = Stage::Waiting;

    ZRQINIT_HEADER.write(port)?;
    loop {
        port.flush()?;

        match read_zpad(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => continue,
            Err(err) => return Err(err),
            _ => (),
        }

        let frame = match Header::read(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                ZNAK_HEADER.write(port)?;
                continue;
            }
            Err(err) => return Err(err),
            Ok(frame) => frame,
        };

        match frame.frame_type() {
            Type::ZRINIT => match stage {
                Stage::Waiting => {
                    write_zfile(port, filename, filesize)?;
                    stage = Stage::Ready;
                }
                Stage::Ready => (),
                Stage::Receiving => ZFIN_HEADER.write(port)?,
            },
            Type::ZRPOS | Type::ZACK => {
                if stage == Stage::Waiting {
                    ZRQINIT_HEADER.write(port)?;
                } else {
                    write_zdata(port, file, &frame)?;
                    stage = Stage::Receiving;
                }
            }
            _ => {
                if stage == Stage::Waiting {
                    ZRQINIT_HEADER.write(port)?;
                } else {
                    port.write_all("OO".as_bytes())?;
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Receives a file using the ZMODEM file transfer protocol.
pub fn read<P, F>(port: &mut P, file: &mut F) -> Result<usize>
where
    P: Read + Write,
    F: Write,
{
    let port = &mut port::Port::new(port);
    let mut stage = Stage::Waiting;
    let mut count = 0;

    ZRINIT_HEADER.write(port)?;

    loop {
        match read_zpad(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => continue,
            Err(err) => return Err(err),
            _ => (),
        }

        let frame = match Header::read(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                ZNAK_HEADER.write(port)?;
                continue;
            }
            Err(err) => return Err(err),
            Ok(frame) => frame,
        };

        match frame.frame_type() {
            Type::ZFILE => match stage {
                Stage::Waiting | Stage::Ready => {
                    read_zfile(frame.encoding(), &count, port)?;
                    stage = Stage::Ready;
                }
                Stage::Receiving => (),
            },
            Type::ZDATA => match stage {
                Stage::Ready | Stage::Receiving => {
                    if frame.count() != count {
                        ZRPOS_HEADER.with_count(count).write(port)?
                    } else {
                        read_zdata(frame.encoding() as u8, &mut count, port, file)?;
                    }
                    stage = Stage::Receiving;
                }
                Stage::Waiting => ZRINIT_HEADER.write(port)?,
            },
            Type::ZEOF if stage == Stage::Receiving => {
                if frame.count() != count {
                    log::error!(
                        "ZEOF offset mismatch: frame({}) != recv({})",
                        frame.count(),
                        count
                    );
                } else {
                    ZRINIT_HEADER.write(port)?
                }
            }
            Type::ZFIN if stage == Stage::Receiving => {
                ZFIN_HEADER.write(port)?;
                break;
            }
            _ if stage == Stage::Waiting => {
                ZRINIT_HEADER.write(port)?;
            }
            _ => (),
        }
    }

    Ok(count as usize)
}

/// Sends a ZFILE packet
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

/// Receives a ZFILE packet
fn read_zfile<P>(encoding: Encoding, count: &u32, port: &mut P) -> Result<()>
where
    P: Write + Read,
{
    let mut buf = Vec::new();

    match read_subpacket(port, encoding, &mut buf) {
        Err(ref err) if err.kind() == ErrorKind::InvalidData => ZNAK_HEADER.write(port),
        Err(err) => Err(err),
        _ => {
            // TODO: Process filename and length.
            ZRPOS_HEADER.with_count(*count).write(port)
        }
    }
}

/// Writes a ZDATA
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

/// Reads a ZDATA packet
fn read_zdata<P, F>(encoding: u8, count: &mut u32, port: &mut P, file: &mut F) -> Result<()>
where
    P: Write + Read,
    F: Write,
{
    let mut buf = Vec::new();

    loop {
        buf.clear();

        let encoding = match encoding.try_into() {
            Ok(encoding) => encoding,
            Err(_) => return Err(ErrorKind::InvalidData.into()),
        };

        let zcrc = match read_subpacket(port, encoding, &mut buf) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                ZRPOS_HEADER.with_count(*count).write(port)?;
                return Err(ErrorKind::InvalidData.into());
            }
            Err(err) => return Err(err),
            Ok(zcrc) => zcrc,
        };

        file.write_all(&buf)?;
        *count += buf.len() as u32;

        match zcrc {
            subpacket::Type::ZCRCW => {
                ZACK_HEADER.with_count(*count).write(port)?;
                return Ok(());
            }
            subpacket::Type::ZCRCE => return Ok(()),
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
fn read_zpad<P>(port: &mut P) -> Result<()>
where
    P: Read,
{
    let mut buf = [0; 1];

    let mut value = port.read_exact(&mut buf).map(|_| buf[0])?;
    if value != ZPAD {
        return Err(ErrorKind::InvalidData.into());
    }

    value = port.read_exact(&mut buf).map(|_| buf[0])?;
    if value == ZPAD {
        value = port.read_exact(&mut buf).map(|_| buf[0])?;
    }

    if value == ZDLE {
        Ok(())
    } else {
        Err(ErrorKind::InvalidData.into())
    }
}

/// Reads and unescapes a ZMODEM protocol subpacket
fn read_subpacket<P>(
    port: &mut P,
    encoding: Encoding,
    buf: &mut Vec<u8>,
) -> io::Result<subpacket::Type>
where
    P: Read,
{
    let result;

    loop {
        let mut byte = [0; 1];
        let byte = port.read_exact(&mut byte).map(|_| byte[0])?;
        if byte == ZDLE {
            let mut byte = [0; 1];
            let byte = port.read_exact(&mut byte).map(|_| byte[0])?;
            if let Ok(sp_type) = subpacket::Type::try_from(byte) {
                buf.push(sp_type as u8);
                result = sp_type;
                break;
            } else {
                buf.push(unescape(byte));
            }
        } else {
            buf.push(byte);
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
        return Err(ErrorKind::InvalidData.into());
    }

    // Pop ZCRC
    buf.pop().unwrap();

    Ok(result)
}

fn read_exact_unescaped<R>(mut r: R, buf: &mut [u8]) -> Result<()>
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
        read_subpacket, read_zpad, subpacket, write_subpacket, XON, ZDLE, ZPAD,
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
    #[case(&[ZPAD, ZDLE], Ok(()))]
    #[case(&[ZPAD, ZPAD, ZDLE], Ok(()))]
    #[case(&[ZDLE], Err(std::io::ErrorKind::InvalidData.into()))]
    #[case(&[], Err(std::io::ErrorKind::UnexpectedEof.into()))]
    #[case(&[0; 100], Err(std::io::ErrorKind::InvalidData.into()))]
    pub fn test_read_zpad(#[case] port: &[u8], #[case] expected: std::io::Result<()>) {
        let result = read_zpad(&mut port.to_vec().as_slice());
        if result.is_err() {
            assert_eq!(result.unwrap_err().kind(), expected.unwrap_err().kind());
        }
    }

    #[rstest::rstest]
    #[case(&[Encoding::ZHEX as u8, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'], &Header::new(Encoding::ZHEX, Type::ZRINIT).with_flags(&[0x1, 0x2, 0x3, 0x4]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb], &Header::new(Encoding::ZBIN, Type::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN32 as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a], &Header::new(Encoding::ZBIN32, Type::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, ZDLE, b'l', 0xd, ZDLE, b'm', 0x5e, 0x6f], &Header::new(Encoding::ZBIN, Type::ZRINIT).with_flags(&[0xa, 0x7f, 0xd, 0xff]))]
    pub fn test_header_read(#[case] input: &[u8], #[case] expected: &Header) {
        let input = input.to_vec();
        assert_eq!(&mut Header::read(&mut input.as_slice()).unwrap(), expected);
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
            subpacket_type
        );

        assert_eq!(&output[..], data);
    }
}
