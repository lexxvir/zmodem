// SPDX-License-Identifier: MIT OR Apache-2.0

use core::convert::TryFrom;
use hex::*;
use log::LogLevel::Debug;
use std::io;

use crate::consts::*;
use crate::frame::{escape_u8_array, new_frame, Encoding, Header, Type};

/// Looking for sequence: ZPAD [ZPAD] ZLDE
/// Returns true if found otherwise false
pub fn find_zpad<R>(r: &mut R) -> io::Result<bool>
where
    R: io::Read,
{
    // looking for first ZPAD
    if read_byte(r)? != ZPAD {
        return Ok(false);
    }

    // get next byte
    let mut b = read_byte(r)?;

    // skip second ZPAD
    if b == ZPAD {
        b = read_byte(r)?;
    }

    // expect ZLDE
    if b != ZLDE {
        return Ok(false);
    }

    Ok(true)
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
fn read_exact_unescaped<R>(mut r: R, buf: &mut [u8]) -> io::Result<()>
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
                debug!("ZCRCW: CRC next, ZACK expected, end of frame");
                write_zack(rw, *count)?;
                return Ok(true);
            }
            ZCRCE => {
                debug!("ZCRCE: CRC next, frame ends, header packet follows");
                return Ok(true);
            }
            ZCRCQ => {
                debug!("ZCRCQ: CRC next, frame continues, ZACK expected");
                write_zack(rw, *count)?
            }
            ZCRCG => {
                debug!("CCRCG: CRC next, frame continues nonstop");
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

/// Writes ZRINIT frame
pub fn write_zrinit<W>(w: &mut W) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZRINIT");

    let mut out = vec![];
    new_frame(
        &Header::new(Encoding::ZHEX, Type::ZRINIT, &[0, 0, 0, 0x23]),
        &mut out,
    );
    w.write_all(&out)
}

/// Writes ZRQINIT frame
pub fn write_zrqinit<W>(w: &mut W) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZRQINIT");

    let mut out = vec![];
    new_frame(
        &Header::new(Encoding::ZHEX, Type::ZRQINIT, &[0, 0, 0, 0x23]),
        &mut out,
    );
    w.write_all(&out)
}

/// Writes ZFILE frame
pub fn write_zfile<W>(w: &mut W, filename: &str, filesize: Option<u32>) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZFILE");

    let mut out = vec![];
    new_frame(
        &Header::new(Encoding::ZBIN32, Type::ZFILE, &[0, 0, 0, 0x23]),
        &mut out,
    );
    w.write_all(&out)?;

    let mut zfile_data = format!("{}\0", filename);
    if let Some(size) = filesize {
        zfile_data += &format!(" {}", size);
    }
    zfile_data += "\0";

    write_zlde_data(w, ZCRCW, zfile_data.as_bytes())
}

/// Writes ZACK frame
pub fn write_zack<W>(w: &mut W, count: u32) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZACK {}", count);

    let mut out = vec![];
    new_frame(
        &Header::new_count(Encoding::ZHEX, Type::ZACK, count),
        &mut out,
    );

    w.write_all(&out)
}

/// Writes ZFIN frame
pub fn write_zfin<W>(w: &mut W) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZFIN");

    let mut out = vec![];
    new_frame(&Header::new(Encoding::ZHEX, Type::ZFIN, &[0; 4]), &mut out);

    w.write_all(&out)
}

/// Writes ZNAK frame
pub fn write_znak<W>(w: &mut W) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZNAK");

    let mut out = vec![];
    new_frame(&Header::new(Encoding::ZHEX, Type::ZNAK, &[0; 4]), &mut out);

    w.write_all(&out)
}

/// Writes ZRPOS frame
pub fn write_zrpos<W>(w: &mut W, count: u32) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZRPOS {}", count);

    let mut out = vec![];
    new_frame(
        &Header::new_count(Encoding::ZHEX, Type::ZRPOS, count),
        &mut out,
    );

    w.write_all(&out)
}

/// Writes ZDATA frame
pub fn write_zdata<W>(w: &mut W, offset: u32) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZDATA {}", offset);

    let mut out = vec![];
    new_frame(
        &Header::new_count(Encoding::ZBIN32, Type::ZDATA, offset),
        &mut out,
    );

    w.write_all(&out)
}

/// Writes ZEOF frame
pub fn write_zeof<W>(w: &mut W, offset: u32) -> io::Result<()>
where
    W: io::Write,
{
    log::trace!("ZEOF {}", offset);

    let mut out = vec![];
    new_frame(
        &Header::new_count(Encoding::ZBIN32, Type::ZEOF, offset),
        &mut out,
    );

    w.write_all(&out)
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
    //let mut w = io::BufWriter::new(w);

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

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]

    use crate::consts::*;
    use crate::frame::*;
    use crate::proto::*;

    #[test]
    fn test_find_zpad() {
        let v = vec![ZPAD, ZLDE];
        assert!(find_zpad(&mut v.as_slice()).unwrap());

        let v = vec![ZPAD, ZPAD, ZLDE];
        assert!(find_zpad(&mut v.as_slice()).unwrap());

        let v = vec![ZLDE];
        assert!(!find_zpad(&mut v.as_slice()).unwrap());

        let v = vec![];
        assert!(find_zpad(&mut v.as_slice()).is_err());

        let v = vec![0; 100];
        assert!(!find_zpad(&mut v.as_slice()).unwrap());
    }

    #[test]
    fn test_read_exact_unescaped() {
        let i = [0; 32];
        let mut o = [0; 32];
        read_exact_unescaped(&i[..], &mut o).unwrap();
        assert_eq!(i, o);

        let i = [ZLDE, b'm', ZLDE, b'l', ZLDE, 0x6f];
        let mut o = [0; 3];
        read_exact_unescaped(&i[..], &mut o).unwrap();
        assert_eq!(o, [0xff, 0x7f, 0x2f]);

        let i = [ZLDE, b'm', 0, 2, ZLDE, b'l'];
        let mut o = [0; 4];
        read_exact_unescaped(&i[..], &mut o).unwrap();
        assert_eq!(o, [0xff, 0, 2, 0x7f]);
    }

    #[test]
    fn test_parse_header() {
        let i = [
            Encoding::ZHEX as u8,
            b'0',
            b'1',
            b'0',
            b'1',
            b'0',
            b'2',
            b'0',
            b'3',
            b'0',
            b'4',
            b'a',
            b'7',
            b'5',
            b'2',
        ];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            &Header::new(Encoding::ZHEX, Type::ZRINIT).flags(&[0x1, 0x2, 0x3, 0x4])
        );

        let i = [
            Encoding::ZBIN as u8,
            Type::ZRINIT as u8,
            0xa,
            0xb,
            0xc,
            0xd,
            0xa6,
            0xcb,
        ];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            &Header::new(Encoding::ZBIN, Type::ZRINIT).flags(&[0xa, 0xb, 0xc, 0xd])
        );

        let i = [
            Encoding::ZBIN32 as u8,
            Type::ZRINIT as u8,
            0xa,
            0xb,
            0xc,
            0xd,
            0x99,
            0xe2,
            0xae,
            0x4a,
        ];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            &Header::new(Encoding::ZBIN32, Type::ZRINIT).flags(&[0xa, 0xb, 0xc, 0xd])
        );

        let i = [
            Encoding::ZBIN as u8,
            Type::ZRINIT as u8,
            0xa,
            ZLDE,
            b'l',
            0xd,
            ZLDE,
            b'm',
            0x5e,
            0x6f,
        ];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            &Header::new(Encoding::ZBIN, Type::ZRINIT).flags(&[0xa, 0x7f, 0xd, 0xff])
        );

        let frame = Type::ZRINIT;
        let i = [0xaa, frame as u8, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf];
        assert_eq!(parse_header(&i[..]).unwrap_or(None), None);
    }

    #[test]
    fn test_recv_zlde_frame() {
        let i = vec![ZLDE, ZCRCE, 237, 174];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCE)
        );
        assert_eq!(&v[..], []);

        let i = vec![ZLDE, 0x00, ZLDE, ZCRCW, 221, 205];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCW)
        );
        assert_eq!(&v[..], [0x00]);

        let i = vec![
            0, 1, 2, 3, 4, ZLDE, 0x60, ZLDE, 0x60, ZLDE, ZCRCQ, 85, 114, 241, 70,
        ];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN32, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCQ)
        );
        assert_eq!(&v[..], [0, 1, 2, 3, 4, 0x20, 0x20]);
    }
}
