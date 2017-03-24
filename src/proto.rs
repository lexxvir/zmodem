use std::io;
use hex::*;
use log::LogLevel::{Debug};

use consts::*;
use frame::*;
use crc::*;

/// Looking for sequence: ZPAD [ZPAD] ZLDE
/// Returns true if found otherwise false
pub fn find_zpad<R>(r: &mut R) -> io::Result<bool>
    where R: io::Read {

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

pub fn parse_header<'a, R>(mut r: R) -> io::Result<Option<Frame>>
    where R: io::Read {

    let header = read_byte(&mut r)?;

    match header {
       ZBIN32 | ZBIN | ZHEX => (),
       _ => {
           error!("unexpected header byte!");
           return Ok(None)
       },
    };

    let len = 1 + 4; // frame type + flags
    let len = if header == ZBIN32 { 4 } else { 2 } + len;
    let len = if header == ZHEX { len * 2 } else { len };
    let mut v = vec![0; len];

    read_exact_unescaped(r, &mut v)?;

    if header == ZHEX {
        v = match FromHex::from_hex(&v) {
            Ok(x) => x,
            _     => {
                error!("from_hex error");
                return Ok(None);
            },
        }
    }

    let crc1 = v[5..].to_vec();
    let crc2 = match header {
        ZBIN32 => get_crc32(&v[..5], None).to_vec(),
        _      => get_crc16(&v[..5], None).to_vec(),
    };

    if crc1 != crc2 {
        error!("crc mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    let mut frame = Frame::new(header, v[0]);
    frame.flags(&[v[1], v[2], v[3], v[4]]);

    if log_enabled!(Debug) {
        debug!("Got frame: {}", frame);
        match frame.get_frame_type() {
            ZACK | ZRPOS => debug!("  offset = {}", frame.get_count()),
            _  => (),
        }
    }

    Ok(Some(frame))
}

/// Read out up to len bytes and remove escaped ones
fn read_exact_unescaped<R>(mut r: R, buf: &mut [u8]) -> io::Result<()>
    where R: io::Read {

    for x in buf {
        *x = match read_byte(&mut r)? {
            ZLDE => unescape(read_byte(&mut r)?),
            y    => y,
        };
    }

    Ok(())
}

/// Receives sequence: <escaped data> ZLDE ZCRC* <CRC bytes>
/// Unescapes sequencies such as 'ZLDE <escaped byte>'
/// If Ok returns <unescaped data> in buf and ZCRC* byte as return value
pub fn recv_zlde_frame<R>(header: u8, r: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<u8>>
    where R: io::BufRead {

    loop {
        r.read_until(ZLDE, buf)?;
        let b = read_byte(r)?;

        if !is_escaped(b) {
            *buf.last_mut().unwrap() = b; // replace ZLDE by ZCRC* byte
            break;
        }

        *buf.last_mut().unwrap() = unescape(b);
    }

    let crc_len = if header == ZBIN32 { 4 } else { 2 };
    let mut crc1 = vec![0; crc_len];

    read_exact_unescaped(r, &mut crc1)?;

    let crc2 = match header {
        ZBIN32 => get_crc32(buf, None).to_vec(),
        _      => get_crc16(buf, None).to_vec(),
    };

    if crc1 != crc2 {
        error!("crc mismatch: {:?} != {:?}", crc1, crc2);
        return Ok(None);
    }

    Ok(buf.pop()) // pop ZCRC* byte
}

pub fn recv_data<RW, OUT>(header: u8, count: &mut u32, rw: &mut RW, out: &mut OUT) -> io::Result<bool> 
    where RW: io::Write + io::BufRead,
         OUT: io::Write {

    let mut buf = Vec::new();

    loop {
        buf.clear();

        let zcrc = match recv_zlde_frame(header, rw, &mut buf)? {
            Some(x) => x,
            None    => return Ok(false),
        };

        out.write_all(&buf)?;
        *count += buf.len() as u32;

        match zcrc {
            ZCRCW => {
                debug!("ZCRCW: CRC next, ZACK expected, end of frame");
                write_zack(rw, *count)?;
                return Ok(true);
            },
            ZCRCE => {
                debug!("ZCRCE: CRC next, frame ends, header packet follows");
                return Ok(true);
            },
            ZCRCQ => {
                debug!("ZCRCQ: CRC next, frame continues, ZACK expected");
                write_zack(rw, *count)?
            },
            ZCRCG => {
                debug!("CCRCG: CRC next, frame continues nonstop");
            },
            _     => {
                panic!(format!("unexpected ZCRC byte: {:02X}", zcrc));
            },
        }
    }
}

/// Converts escaped byte to unescaped one
fn unescape(escaped_byte: u8) -> u8 {
    match escaped_byte {
        ESC_FF => 0xFF,
        ESC_7F => 0x7F,
        x      => if x & 0x60 != 0 { x ^ 0x40 } else { x },
    }
}

fn is_escaped(byte: u8) -> bool {
	match byte {
		ZCRCE | ZCRCG | ZCRCQ | ZCRCW => false,
        _ => true,
	}
}

/// Reads out one byte
fn read_byte<R>(r: &mut R) -> io::Result<u8>
    where R: io::Read {
    let mut b = [0; 1];
    r.read_exact(&mut b).map(|_| b[0])
}

/// Writes ZRINIT frame
pub fn write_zrinit<W>(w: &mut W) -> io::Result<()>
    where W: io::Write {

    debug!("write ZRINIT");
    w.write_all(&Frame::new(ZHEX, ZRINIT).flags(&[0, 0, 0, 0x23]).build())
}

/// Writes ZRQINIT frame
pub fn write_zrqinit<W>(w: &mut W) -> io::Result<()>
    where W: io::Write {

    debug!("write ZRQINIT");
    w.write_all(&Frame::new(ZHEX, ZRQINIT).build())
}

/// Writes ZFILE frame
pub fn write_zfile<W>(w: &mut W, filename: &str, filesize: Option<u32>) -> io::Result<()>
    where W: io::Write {

    debug!("write ZFILE");
    w.write_all(&Frame::new(ZBIN32, ZFILE).build())?;

    let mut zfile_data = format!("{}\0", filename);
    if let Some(size) = filesize {
        zfile_data += &format!(" {}", size);
    }
    zfile_data += &format!("\0");

    debug!("ZFILE supplied data: {}", zfile_data);
    write_zlde_data(w, ZCRCW, zfile_data.as_bytes())
}

/// Writes ZACK frame
pub fn write_zack<W>(w: &mut W, count: u32) -> io::Result<()>
    where W: io::Write {

    debug!("write ZACK bytes={}", count);
    w.write_all(&Frame::new(ZHEX, ZACK).count(count).build())
}

/// Writes ZFIN frame
pub fn write_zfin<W>(w: &mut W) -> io::Result<()>
    where W: io::Write {

    debug!("write ZFIN");
    w.write_all(&Frame::new(ZHEX, ZFIN).build())
}

/// Writes ZNAK frame
pub fn write_znak<W>(w: &mut W) -> io::Result<()>
    where W: io::Write {

    debug!("write ZNAK");
    w.write_all(&Frame::new(ZHEX, ZNAK).build())
}

/// Writes ZRPOS frame
pub fn write_zrpos<W>(w: &mut W, count: u32) -> io::Result<()>
    where W: io::Write {

    debug!("write ZRPOS bytes={}", count);
    w.write_all(&Frame::new(ZHEX, ZRPOS).count(count).build())
}

/// Writes ZDATA frame
pub fn write_zdata<W>(w: &mut W, offset: u32) -> io::Result<()>
    where W: io::Write {

    debug!("write ZDATA offset={}", offset);
    w.write_all(&Frame::new(ZBIN32, ZDATA).count(offset).build())
}

/// Writes ZEOF frame
pub fn write_zeof<W>(w: &mut W, offset: u32) -> io::Result<()>
    where W: io::Write {

    debug!("write ZEOF offset={}", offset);
    w.write_all(&Frame::new(ZBIN32, ZEOF).count(offset).build())
}

pub fn write_zlde_data<W>(w: &mut W, zcrc_byte: u8, data: &[u8]) -> io::Result<()>
    where W: io::Write {

    if log_enabled!(Debug) {
        debug!("  ZCRC{} subpacket, size = {}",
               match zcrc_byte {
                   ZCRCE => "E",
                   ZCRCG => "G",
                   ZCRCQ => "Q",
                   ZCRCW => "W",
                   _     => "?",
               },
               data.len());
    }

    let crc = get_crc32(data, Some(zcrc_byte));

    write_escape(w, data)?;
    w.write(&[ZLDE, zcrc_byte])?;
    write_escape(w, &crc)?;

    Ok(())
}

fn write_escape<W>(w: &mut W, data: &[u8]) -> io::Result<()>
    where W: io::Write {

    //let mut w = io::BufWriter::new(w);

    let mut esc_data = Vec::with_capacity(data.len() + data.len()/10);
    escape_buf(data, &mut esc_data);
    w.write_all(&esc_data)
}

/// Writes "Over & Out"
pub fn write_over_and_out<W>(w: &mut W) -> io::Result<()>
    where W: io::Write
{
    w.write_all("OO".as_bytes())
}


pub fn escape_buf(src: &[u8], dst: &mut Vec<u8>) {
    for x in src {
        match *x {
            0xFF => dst.extend_from_slice(&[ZLDE, ESC_FF]),
            0x7F => dst.extend_from_slice(&[ZLDE, ESC_7F]),
            0x10 | 0x90 | 0x11 | 0x91 | 0x13 | 0x93
                 => dst.extend_from_slice(&[ZLDE, x ^ 0x40]),
            ZLDE => dst.extend_from_slice(&[ZLDE, ZLDEE]),
            x    => dst.push(x),
        };
    }
}

mod tests {
    #![allow(unused_imports)]

    use consts::*;
    use frame::*;
    use super::*;

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
        let i = [ZHEX, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            Frame::new(ZHEX, 1).flags(&[0x1, 0x2, 0x3, 0x4]));

        let frame = 1;
        let i = [ZBIN, frame, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            Frame::new(ZBIN, frame).flags(&[0xa, 0xb, 0xc, 0xd]));

        let frame = 1;
        let i = [ZBIN32, frame, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            Frame::new(ZBIN32, frame).flags(&[0xa, 0xb, 0xc, 0xd]));

        let frame = 1;
        let i = [ZBIN, frame, 0xa, ZLDE, b'l', 0xd, ZLDE, b'm', 0x5e, 0x6f];
        assert_eq!(
            &mut parse_header(&i[..]).unwrap().unwrap(),
            Frame::new(ZBIN, frame).flags(&[0xa, 0x7f, 0xd, 0xff]));

        let frame = 1;
        let i = [0xaa, frame, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf];
        assert_eq!(parse_header(&i[..]).unwrap(), None);
    }

    #[test]
    fn test_recv_zlde_frame() {
        let i = vec![ZLDE, ZCRCE, 237, 174];
        let mut v = vec![];
        assert_eq!(recv_zlde_frame(ZBIN, &mut i.as_slice(), &mut v).unwrap(), Some(ZCRCE));
        assert_eq!(&v[..], []);

        let i = vec![ZLDE, 0x00, ZLDE, ZCRCW, 221, 205];
        let mut v = vec![];
        assert_eq!(recv_zlde_frame(ZBIN, &mut i.as_slice(), &mut v).unwrap(), Some(ZCRCW));
        assert_eq!(&v[..], [0x00]);

        let i = vec![0, 1, 2, 3, 4, ZLDE, 0x60, ZLDE, 0x60, ZLDE, ZCRCQ, 85, 114, 241, 70];
        let mut v = vec![];
        assert_eq!(recv_zlde_frame(ZBIN32, &mut i.as_slice(), &mut v).unwrap(), Some(ZCRCQ));
        assert_eq!(&v[..], [0, 1, 2, 3, 4, 0x20, 0x20]);
    }
}
