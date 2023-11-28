// SPDX-License-Identifier: MIT OR Apache-2.0

use core::convert::TryFrom;
use hex::*;
use log::LogLevel::Debug;
use std::io::{self, BufRead, ErrorKind};

use crate::consts::*;
use crate::frame::{escape_u8_array, Encoding, Frame, Header, Type};

/// Skips (ZPAD, [ZPAD,] ZLDE) sequence
pub fn try_skip_zpad<P>(port: &mut P) -> io::Result<bool>
where
    P: BufRead,
{
    let mut read_buf = [0; 1];

    let mut value = port.read_exact(&mut read_buf).map(|_| read_buf[0])?;
    if value != ZPAD {
        return Ok(false);
    }

    value = port.read_exact(&mut read_buf).map(|_| read_buf[0])?;
    if value == ZPAD {
        value = port.read_exact(&mut read_buf).map(|_| read_buf[0])?;
    }

    if value == ZLDE {
        Ok(true)
    } else {
        Err(ErrorKind::InvalidData.into())
    }
}

pub fn parse_header<R>(mut r: R) -> io::Result<Option<Header>>
where
    R: io::Read,
{
    // Read encoding byte:
    let enc_raw = read_byte(&mut r)?;

    // Parse encoding byte:
    let encoding = match Encoding::try_from(enc_raw) {
        Ok(enc) => enc,
        Err(_) => return Ok(None),
    };

    let len = 1 + 4; // frame type + flags
    let len = if encoding == Encoding::ZBIN32 { 4 } else { 2 } + len;
    let len = if encoding == Encoding::ZHEX {
        len * 2
    } else {
        len
    };
    let mut v: Vec<u8> = vec![0; len];

    read_exact_unescaped(r, &mut v)?;

    if encoding == Encoding::ZHEX {
        v = match FromHex::from_hex(&v) {
            Ok(x) => x,
            _ => {
                error!("from_hex error");
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
        error!("crc mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    // Read encoding byte:
    let ft_raw: u8 = v[0];

    // Parse encoding byte:
    let ft = match Type::try_from(ft_raw) {
        Ok(ft) => ft,
        Err(_) => return Ok(None),
    };

    let header = Header::new(encoding, ft, &[v[1], v[2], v[3], v[4]]);
    log::trace!("FRAME {}", header);
    Ok(Some(header))
}

/// Read out up to len bytes and remove escaped ones
pub fn read_exact_unescaped<R>(mut r: R, buf: &mut [u8]) -> io::Result<()>
where
    R: io::Read,
{
    for x in buf {
        *x = match read_byte(&mut r)? {
            ZLDE => unescape(read_byte(&mut r)?),
            y => y,
        };
    }

    Ok(())
}

/// Receives sequence: <escaped data> ZLDE ZCRC* <CRC bytes>
/// Unescapes sequencies such as 'ZLDE <escaped byte>'
/// If Ok returns <unescaped data> in buf and ZCRC* byte as return value
pub fn recv_zlde_frame<R>(
    encoding: Encoding,
    r: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<Option<u8>>
where
    R: io::BufRead,
{
    loop {
        r.read_until(ZLDE, buf)?;
        let b = read_byte(r)?;

        if !is_escaped(b) {
            *buf.last_mut().unwrap() = b; // replace ZLDE by ZCRC* byte
            break;
        }

        *buf.last_mut().unwrap() = unescape(b);
    }

    let crc_len = if encoding == Encoding::ZBIN32 { 4 } else { 2 };
    let mut crc1 = vec![0; crc_len];

    read_exact_unescaped(r, &mut crc1)?;

    let crc2 = match encoding {
        Encoding::ZBIN32 => CRC32.checksum(buf).to_le_bytes().to_vec(),
        _ => CRC16.checksum(buf).to_be_bytes().to_vec(),
    };

    if crc1 != crc2 {
        error!("crc mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    Ok(buf.pop()) // pop ZCRC* byte
}

pub fn recv_data<RW, OUT>(
    enc_raw: u8,
    count: &mut u32,
    rw: &mut RW,
    out: &mut OUT,
) -> io::Result<bool>
where
    RW: io::Write + io::BufRead,
    OUT: io::Write,
{
    let mut buf = Vec::new();

    loop {
        buf.clear();

        // Parse encoding byte:
        let encoding = match Encoding::try_from(enc_raw) {
            Ok(enc) => enc,
            Err(_) => return Ok(false),
        };

        // Read and parse ZLDE frame:
        let zcrc = match recv_zlde_frame(encoding, rw, &mut buf)? {
            Some(x) => x,
            None => return Ok(false),
        };

        out.write_all(&buf)?;
        *count += buf.len() as u32;

        match zcrc {
            ZCRCW => {
                let frame = Frame::new(&Header::new_count(Encoding::ZHEX, Type::ZACK, *count));
                rw.write_all(&frame.0)?;
                return Ok(true);
            }
            ZCRCE => {
                return Ok(true);
            }
            ZCRCQ => {
                let frame = Frame::new(&Header::new_count(Encoding::ZHEX, Type::ZACK, *count));
                rw.write_all(&frame.0)?;
            }
            ZCRCG => {
                log::debug!("ZCRCG");
            }
            _ => {
                panic!("unexpected ZCRC byte: {:02X}", zcrc);
            }
        }
    }
}

/// Converts escaped byte to unescaped one
fn unescape(escaped_byte: u8) -> u8 {
    match escaped_byte {
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

fn is_escaped(byte: u8) -> bool {
    !matches!(byte, ZCRCE | ZCRCG | ZCRCQ | ZCRCW)
}

/// Reads out one byte
fn read_byte<R>(r: &mut R) -> io::Result<u8>
where
    R: io::Read,
{
    let mut b = [0; 1];
    r.read_exact(&mut b).map(|_| b[0])
}

/// Writes ZFILE data
pub fn write_zfile_data<W>(w: &mut W, filename: &str, filesize: Option<u32>) -> io::Result<()>
where
    W: io::Write,
{
    let mut zfile_data = format!("{}\0", filename);
    if let Some(size) = filesize {
        zfile_data += &format!(" {}", size);
    }
    zfile_data += "\0";

    write_zlde_data(w, ZCRCW, zfile_data.as_bytes())
}

pub fn write_zlde_data<W>(w: &mut W, zcrc_byte: u8, data: &[u8]) -> io::Result<()>
where
    W: io::Write,
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

fn write_escape<W>(w: &mut W, data: &[u8]) -> io::Result<()>
where
    W: io::Write,
{
    let mut esc_data = Vec::with_capacity(data.len() + data.len() / 10);
    escape_u8_array(data, &mut esc_data);
    w.write_all(&esc_data)
}

/// Writes "Over & Out"
pub fn write_over_and_out<W>(w: &mut W) -> io::Result<()>
where
    W: io::Write,
{
    w.write_all("OO".as_bytes())
}
