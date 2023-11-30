// SPDX-License-Identifier: MIT OR Apache-2.0

mod frame;
mod port;
mod subpacket;

use core::convert::TryFrom;
use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};
use frame::{Encoding, Frame, Header, Type};
use hex::FromHex;
use std::io::{self, BufRead, Read, Result, Seek, SeekFrom, Write};
use std::str::from_utf8;

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const ZACK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZACK, &[0; 4]);
pub const ZDATA_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZDATA, &[0; 4]);
pub const ZEOF_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZEOF, &[0; 4]);
pub const ZFILE_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZFILE, &[0, 0, 0, 0x23]);
pub const ZFIN_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZFIN, &[0; 4]);
pub const ZNAK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZNAK, &[0; 4]);
pub const ZRINIT_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRINIT, &[0, 0, 0, 0x23]);
pub const ZRPOS_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRPOS, &[0; 4]);
pub const ZRQINIT_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRQINIT, &[0, 0, 0, 0x23]);

pub const ZPAD: u8 = b'*';
pub const ZDLE: u8 = 0x18;
pub const ZDLEE: u8 = 0x58;

pub const ESC_FF: u8 = b'm';
pub const ESC_7F: u8 = b'l';

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

    port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?;
    loop {
        port.flush()?;
        if !skip_zpad(&mut port)? {
            continue;
        }
        let frame = match parse_header(&mut port)? {
            Some(x) => x,
            None => {
                port.write_all(&Frame::new(&ZNAK_HEADER).0)?;
                continue;
            }
        };

        match stage {
            Stage::Waiting => match frame.frame_type() {
                Type::ZRINIT => {
                    write_zfile(&mut port, filename, filesize)?;
                    stage = Stage::Ready;
                }
                _ => port.write_all(&Frame::new(&ZRQINIT_HEADER).0)?,
            },
            Stage::Ready => match frame.frame_type() {
                Type::ZRPOS => {
                    write_zdata(&mut port, file, &frame)?;
                    stage = Stage::Receiving;
                }
                Type::ZACK => {
                    write_zdata(&mut port, file, &frame)?;
                    stage = Stage::Receiving;
                }
                Type::ZRINIT => (),
                _ => {
                    port.write_all("OO".as_bytes())?;
                    break;
                }
            },
            Stage::Receiving => match frame.frame_type() {
                Type::ZRPOS => write_zdata(&mut port, file, &frame)?,
                Type::ZACK => write_zdata(&mut port, file, &frame)?,
                Type::ZRINIT => port.write_all(&Frame::new(&ZFIN_HEADER).0)?,
                _ => {
                    port.write_all("OO".as_bytes())?;
                    break;
                }
            },
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

    port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;

    loop {
        if !skip_zpad(&mut port)? {
            continue;
        }

        let frame = match parse_header(&mut port)? {
            Some(frame) => frame,
            None => {
                if stage == Stage::Receiving {
                    port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?;
                } else {
                    port.write_all(&Frame::new(&ZNAK_HEADER).0)?;
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
                    port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;
                }
            },
            Stage::Ready => match frame.frame_type() {
                Type::ZFILE => read_zfile(frame.encoding(), &count, &mut port)?,
                Type::ZDATA => {
                    if frame.count() != count
                        || !read_zdata(frame.encoding() as u8, &mut count, &mut port, file)?
                    {
                        port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?
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
                        port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(count)).0)?
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
                        port.write_all(&Frame::new(&ZRINIT_HEADER).0)?;
                    }
                }
                Type::ZFIN => {
                    port.write_all(&Frame::new(&ZFIN_HEADER).0)?;
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

    port.write_all(&Frame::new(&ZFILE_HEADER).0)?;
    data.extend_from_slice(name.as_bytes());
    data.push(b'\0');
    if let Some(size) = maybe_size {
        data.extend_from_slice(size.to_string().as_bytes());
    }
    data.push(b'\0');
    write_subpacket(port, subpacket::Type::ZCRCW, &data)
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
        write_subpacket(port, subpacket::Type::ZCRCG, &data[..count])?;
        offset += count as u32;

        count = file.read(&mut data)?;
        if count < SUBPACKET_SIZE {
            break;
        }
    }
    write_subpacket(port, subpacket::Type::ZCRCW, &data[..count])?;

    Ok(())
}

fn read_zfile<P>(encoding: Encoding, count: &u32, port: &mut P) -> Result<()>
where
    P: Write + BufRead,
{
    let mut buf = Vec::new();

    if read_subpacket(encoding, port, &mut buf)?.is_none() {
        port.write_all(&Frame::new(&ZNAK_HEADER).0)?;
    } else {
        port.write_all(&Frame::new(&ZRPOS_HEADER.with_count(*count)).0)?;

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

        let zcrc = match read_subpacket(encoding, port, &mut buf)? {
            Some(x) => x,
            None => return Ok(false),
        };

        file.write_all(&buf)?;
        *count += buf.len() as u32;

        match zcrc {
            subpacket::Type::ZCRCW => {
                port.write_all(&Frame::new(&ZACK_HEADER.with_count(*count)).0)?;
                return Ok(true);
            }
            subpacket::Type::ZCRCE => return Ok(true),
            subpacket::Type::ZCRCQ => {
                port.write_all(&Frame::new(&ZACK_HEADER.with_count(*count)).0)?
            }
            subpacket::Type::ZCRCG => log::debug!("ZCRCG"),
        }
    }
}

pub fn escape(value: u8) -> Option<[u8; 2]> {
    Some(match value {
        0xFF => [ZDLE, ESC_FF],
        0x7F => [ZDLE, ESC_7F],
        0x10 | 0x90 | 0x11 | 0x91 | 0x13 | 0x93 => [ZDLE, value ^ 0x40],
        ZDLE => [ZDLE, ZDLEE],
        _ => return None,
    })
}

pub fn unescape(value: u8) -> u8 {
    match value {
        ESC_FF => 0xFF,
        ESC_7F => 0x7F,
        x => {
            if x & 0x60 != 0 {
                x ^ 0x40
            } else {
                x
            }
        }
    }
}

pub fn escape_array(src: &[u8], dst: &mut Vec<u8>) {
    for value in src {
        if let Some(value) = escape(*value) {
            dst.extend_from_slice(&value);
        } else {
            dst.push(*value);
        }
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

fn parse_header<R>(mut r: R) -> io::Result<Option<Header>>
where
    R: Read,
{
    // Read encoding byte:
    let mut enc_raw = [0; 1];
    let enc_raw = r.read_exact(&mut enc_raw).map(|_| enc_raw[0])?;

    // Parse encoding byte:
    let encoding = match Encoding::try_from(enc_raw) {
        Ok(encoding) => encoding,
        Err(_) => return Ok(None),
    };

    let mut v: Vec<u8> = vec![0; Header::encoded_size(encoding) - 1];

    read_exact_unescaped(r, &mut v)?;

    if encoding == Encoding::ZHEX {
        v = match FromHex::from_hex(&v) {
            Ok(x) => x,
            _ => {
                log::error!("from_hex error");
                return Ok(None);
            }
        }
    }

    let crc1 = v[5..].to_vec();
    let crc2 = match encoding {
        Encoding::ZBIN32 => CRC32.checksum(&v[..5]).to_le_bytes().to_vec(),
        _ => CRC16.checksum(&v[..5]).to_be_bytes().to_vec(),
    };

    if crc1 != crc2 {
        log::error!("CRC mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    // Read and parse frame tpye:
    let ft = match Type::try_from(v[0]) {
        Ok(ft) => ft,
        Err(_) => return Ok(None),
    };

    let header = Header::new(encoding, ft, &[v[1], v[2], v[3], v[4]]);
    log::trace!("FRAME {}", header);
    Ok(Some(header))
}

/// Receives sequence: <escaped data> ZDLE ZCRC* <CRC bytes>
/// Unescapes sequencies such as 'ZDLE <escaped byte>'
/// If Ok returns <unescaped data> in buf and ZCRC* byte as return value
fn read_subpacket<F>(
    encoding: Encoding,
    file: &mut F,
    buf: &mut Vec<u8>,
) -> io::Result<Option<subpacket::Type>>
where
    F: io::BufRead,
{
    let result;

    loop {
        file.read_until(ZDLE, buf)?;

        let mut byte = [0; 1];
        let byte = file.read_exact(&mut byte).map(|_| byte[0])?;

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

    read_exact_unescaped(file, &mut crc1)?;

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

fn write_subpacket<P>(port: &mut P, subpacket_type: subpacket::Type, data: &[u8]) -> Result<()>
where
    P: Write,
{
    let subpacket_type = subpacket_type as u8;

    let mut digest = CRC32.digest();
    digest.update(data);
    digest.update(&[subpacket_type]);

    // Assuming little-endian byte order, given that ZMODEM used to work on
    // VAX, which was a little-endian computer architecture:
    let crc = digest.finalize().to_le_bytes();

    let mut esc_data = vec![];
    let mut esc_crc = vec![];

    escape_array(data, &mut esc_data);
    escape_array(&crc, &mut esc_crc);

    port.write_all(&esc_data)?;
    port.write_all(&[ZDLE, subpacket_type])?;
    port.write_all(&esc_crc)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        frame::{Encoding, Frame, Header, Type},
        parse_header, read_subpacket, skip_zpad, subpacket, XON, ZDLE, ZPAD,
    };

    const ZCRCE: u8 = b'h';
    const ZCRCQ: u8 = b'j';
    const ZCRCW: u8 = b'k';

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(Encoding::ZBIN32, Type::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN32 as u8, 0, 0, 0, 0, 0, 29, 247, 34, 198])]
    pub fn test_header(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type, &[0; 4]);
        let frame = Frame::new(&header);
        assert_eq!(frame.0, expected);
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
        let header = Header::new(encoding, frame_type, flags);
        let frame = Frame::new(&header);
        assert_eq!(frame.0, expected);
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
    #[case(&[Encoding::ZHEX as u8, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'], &Header::new(Encoding::ZHEX, Type::ZRINIT, &[0x1, 0x2, 0x3, 0x4]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb], &Header::new(Encoding::ZBIN, Type::ZRINIT, &[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN32 as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a], &Header::new(Encoding::ZBIN32, Type::ZRINIT, &[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, ZDLE, b'l', 0xd, ZDLE, b'm', 0x5e, 0x6f], &Header::new(Encoding::ZBIN, Type::ZRINIT, &[0xa, 0x7f, 0xd, 0xff]))]
    pub fn test_parse_header(#[case] input: &[u8], #[case] expected: &Header) {
        assert_eq!(&mut parse_header(&input[..]).unwrap().unwrap(), expected);
    }

    #[test]
    fn test_parse_header_none() {
        let frame = Type::ZRINIT;
        let i = [0xaa, frame as u8, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf];
        assert_eq!(parse_header(&i[..]).unwrap_or(None), None);
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, &[ZDLE, ZCRCE, 237, 174], Some(subpacket::Type::ZCRCE), &[])]
    #[case(Encoding::ZBIN, &[ZDLE, 0x00, ZDLE, ZCRCW, 221, 205], Some(subpacket::Type::ZCRCW), &[0x00])]
    #[case(Encoding::ZBIN32, &[0, 1, 2, 3, 4, ZDLE, 0x60, ZDLE, 0x60, ZDLE, ZCRCQ, 85, 114, 241, 70], Some(subpacket::Type::ZCRCQ), &[0, 1, 2, 3, 4, 0x20, 0x20])]
    pub fn test_read_subpacket(
        #[case] encoding: Encoding,
        #[case] input: &[u8],
        #[case] expected_result: std::option::Option<subpacket::Type>,
        #[case] expected_output: &[u8],
    ) {
        let input = input.to_vec();
        let mut output = vec![];

        assert_eq!(
            read_subpacket(encoding, &mut input.as_slice(), &mut output).unwrap(),
            expected_result
        );
        assert_eq!(&output[..], expected_output);
    }
}
