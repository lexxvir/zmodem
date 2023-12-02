// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM file transfer protocol

mod port;

use bitflags::bitflags;
use core::convert::TryFrom;
use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};
use std::fmt::{self, Display};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use tinyvec::{array_vec, ArrayVec};

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const ZACK_HEADER: FrameHeader = FrameHeader::new(Encoding::ZHEX, FrameKind::ZACK);
pub const ZDATA_HEADER: FrameHeader = FrameHeader::new(Encoding::ZBIN32, FrameKind::ZDATA);
pub const ZEOF_HEADER: FrameHeader = FrameHeader::new(Encoding::ZBIN32, FrameKind::ZEOF);
pub const ZFILE_HEADER: FrameHeader =
    FrameHeader::new(Encoding::ZBIN32, FrameKind::ZFILE).with_flags(&[0, 0, 0, 0x23]);
pub const ZFIN_HEADER: FrameHeader = FrameHeader::new(Encoding::ZHEX, FrameKind::ZFIN);
pub const ZNAK_HEADER: FrameHeader = FrameHeader::new(Encoding::ZHEX, FrameKind::ZNAK);
pub const ZRINIT_HEADER: FrameHeader =
    FrameHeader::new(Encoding::ZHEX, FrameKind::ZRINIT).with_flags(&[0, 0, 0, 0x23]);
pub const ZRPOS_HEADER: FrameHeader = FrameHeader::new(Encoding::ZHEX, FrameKind::ZRPOS);
pub const ZRQINIT_HEADER: FrameHeader =
    FrameHeader::new(Encoding::ZHEX, FrameKind::ZRQINIT).with_flags(&[0, 0, 0, 0x23]);

pub const ZPAD: u8 = b'*';
pub const ZDLE: u8 = 0x18;

pub const XON: u8 = 0x11;

pub const SUBPACKET_SIZE: usize = 1024 * 8;
pub const SUBPACKET_PER_ACK: usize = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrameHeader {
    encoding: Encoding,
    frame_type: FrameKind,
    flags: [u8; 4],
}

impl FrameHeader {
    pub const fn new(encoding: Encoding, frame_type: FrameKind) -> FrameHeader {
        FrameHeader {
            encoding,
            frame_type,
            flags: [0; 4],
        }
    }

    pub const fn with_count(&self, count: u32) -> Self {
        FrameHeader {
            encoding: self.encoding,
            frame_type: self.frame_type,
            flags: count.to_le_bytes(),
        }
    }

    pub const fn with_flags(&self, flags: &[u8; 4]) -> Self {
        FrameHeader {
            encoding: self.encoding,
            frame_type: self.frame_type,
            flags: *flags,
        }
    }

    /// Returns unescaped size of the header, while being still serialized.
    pub const fn unescaped_size(encoding: Encoding) -> usize {
        match encoding {
            Encoding::ZBIN => core::mem::size_of::<FrameHeader>() + 2,
            Encoding::ZBIN32 => core::mem::size_of::<FrameHeader>() + 4,
            // Encoding is stored as a single byte also for ZHEX, thus the
            // subtraction:
            Encoding::ZHEX => (core::mem::size_of::<FrameHeader>() + 2) * 2 - 1,
        }
    }

    pub const fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub const fn frame_type(&self) -> FrameKind {
        self.frame_type
    }

    pub const fn count(&self) -> u32 {
        u32::from_le_bytes(self.flags)
    }

    pub fn read<P>(port: &mut P) -> io::Result<FrameHeader>
    where
        P: Read,
    {
        // Read encoding byte:
        let mut enc_raw = [0; 1];
        let enc_raw = port.read_exact(&mut enc_raw).map(|_| enc_raw[0])?;

        // Parse encoding byte:
        let encoding = match Encoding::try_from(enc_raw) {
            Ok(encoding) => encoding,
            Err(_) => return Err(ErrorKind::InvalidData.into()),
        };

        let mut out = ArrayVec::<[u8; FrameHeader::unescaped_size(Encoding::ZHEX) - 1]>::new();

        for _ in 0..FrameHeader::unescaped_size(encoding) - 1 {
            out.push(read_byte_unescaped(port)?);
        }

        if encoding == Encoding::ZHEX {
            hex::decode_in_slice(&mut out).or::<io::Error>(Err(ErrorKind::InvalidData.into()))?;
            out.truncate(out.len() / 2);
        }

        check_crc(&out[..5], &out[5..], encoding)?;

        // Read and parse frame tpye:
        let ft = match FrameKind::try_from(out[0]) {
            Ok(ft) => ft,
            Err(_) => return Err(ErrorKind::InvalidData.into()),
        };

        let header = FrameHeader::new(encoding, ft).with_flags(&[out[1], out[2], out[3], out[4]]);
        Ok(header)
    }

    pub fn write<P>(&self, port: &mut P) -> io::Result<()>
    where
        P: Write,
    {
        let mut out = array_vec!([u8; FrameHeader::unescaped_size(Encoding::ZHEX) + 6]);

        out.push(ZPAD);
        if self.encoding == Encoding::ZHEX {
            out.push(ZPAD);
        }
        out.push(ZDLE);

        out.push(self.encoding as u8);
        out.push(self.frame_type as u8);
        out.extend_from_slice(&self.flags);

        // Skips ZPAD and encoding:
        let data = if self.encoding == Encoding::ZHEX {
            &out[4..]
        } else {
            &out[3..]
        };
        let mut crc = [0u8; 4];
        let crc_len = make_crc(data, &mut crc, self.encoding);
        out.extend_from_slice(&crc[..crc_len]);

        // Skips ZPAD and encoding:
        if self.encoding == Encoding::ZHEX {
            let hex = hex::encode(&out[4..]);
            out.truncate(4);
            out.extend_from_slice(hex.as_bytes());
        }

        // FIXME: Remove heap allocation:
        let mut escaped = vec![];
        // Does not corrupt `ZHEX` as the encoding byte is not escaped:
        escape_array(&out[3..], &mut escaped);
        out.truncate(3);
        out.extend_from_slice(&escaped);

        if self.encoding == Encoding::ZHEX {
            // Add trailing CRLF for ZHEX transfer:
            out.extend_from_slice(b"\r\n");

            if self.frame_type != FrameKind::ZACK && self.frame_type != FrameKind::ZFIN {
                out.push(XON);
            }
        }

        port.write_all(&out)
    }
}

impl fmt::Display for FrameHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:8} {}", self.encoding, self.frame_type)
    }
}

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
/// The ZMODEM frame type
pub enum Encoding {
    ZBIN = 0x41,
    ZHEX = 0x42,
    ZBIN32 = 0x43,
}

const ENCODINGS: &[Encoding] = &[Encoding::ZBIN, Encoding::ZHEX, Encoding::ZBIN32];

#[derive(Clone, Copy, Debug)]
pub struct InvalidEncoding;

impl TryFrom<u8> for Encoding {
    type Error = InvalidEncoding;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ENCODINGS
            .iter()
            .find(|e| value == **e as u8)
            .map_or(Err(InvalidEncoding), |e| Ok(*e))
    }
}

impl Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
/// The ZMODEM frame type
pub enum FrameKind {
    /// Request receive init
    ZRQINIT = 0,
    /// Receive init
    ZRINIT = 1,
    /// Send init sequence (optional)
    ZSINIT = 2,
    /// ACK to above
    ZACK = 3,
    /// File name from sender
    ZFILE = 4,
    /// To sender: skip this file
    ZSKIP = 5,
    /// Last packet was garbled
    ZNAK = 6,
    /// Abort batch transfers
    ZABORT = 7,
    /// Finish session
    ZFIN = 8,
    /// Resume data trans at this position
    ZRPOS = 9,
    /// Data packet(s) follow
    ZDATA = 10,
    /// End of file
    ZEOF = 11,
    /// Fatal Read or Write error Detected
    ZFERR = 12,
    /// Request for file CRC and response
    ZCRC = 13,
    /// Receiver's Challenge
    ZCHALLENGE = 14,
    /// Request is complete
    ZCOMPL = 15,
    /// Other end canned session with CAN*5
    ZCAN = 16,
    /// Request for free bytes on filesystem
    ZFREECNT = 17,
    /// Command from sending program
    ZCOMMAND = 18,
    ///  Output to standard error, data follows
    ZSTDERR = 19,
}

const FRAMES: &[FrameKind] = &[
    FrameKind::ZRQINIT,
    FrameKind::ZRINIT,
    FrameKind::ZSINIT,
    FrameKind::ZACK,
    FrameKind::ZFILE,
    FrameKind::ZSKIP,
    FrameKind::ZNAK,
    FrameKind::ZABORT,
    FrameKind::ZFIN,
    FrameKind::ZRPOS,
    FrameKind::ZDATA,
    FrameKind::ZEOF,
    FrameKind::ZFERR,
    FrameKind::ZCRC,
    FrameKind::ZCHALLENGE,
    FrameKind::ZCOMPL,
    FrameKind::ZCAN,
    FrameKind::ZFREECNT,
    FrameKind::ZCOMMAND,
    FrameKind::ZSTDERR,
];

#[derive(Clone, Copy, Debug)]
pub struct InvalidFrameKind;

impl TryFrom<u8> for FrameKind {
    type Error = InvalidFrameKind;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        FRAMES
            .iter()
            .find(|t| value == **t as u8)
            .map_or(Err(InvalidFrameKind), |t| Ok(*t))
    }
}

impl Display for FrameKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

// TODO: Take into use.
bitflags! {
    /// Flags used as part of ZRINIT to notify the sender about receivers
    /// capabilities.
    pub struct ReceiverFlags: u8 {
        /// Can send and receive in full-duplex
        const CANFDX = 0x01;
        /// Can receive data in parallel with disk I/O
        const CANOVIO = 0x02;
        /// Can send a break signal
        const CANBRK = 0x04;
        /// Can decrypt
        const CANCRY = 0x08;
        /// Can uncompress
        const CANLZW = 0x10;
        /// Can use 32-bit frame check
        const CANFC32 = 0x20;
        /// Expects control character to be escaped
        const ESCCTL = 0x40;
        /// Expects 8th bit to be escaped
        const ESC8 = 0x80;
    }
}
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq)]
/// The ZMODEM subpacket type
pub enum PacketKind {
    ZCRCE = 0x68,
    ZCRCG = 0x69,
    ZCRCQ = 0x6a,
    ZCRCW = 0x6b,
}

const PACKETS: &[PacketKind] = &[
    PacketKind::ZCRCE,
    PacketKind::ZCRCG,
    PacketKind::ZCRCQ,
    PacketKind::ZCRCW,
];

#[derive(Clone, Copy, Debug)]
pub struct InvalidPacketKind;

impl TryFrom<u8> for PacketKind {
    type Error = InvalidPacketKind;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        PACKETS
            .iter()
            .find(|e| value == **e as u8)
            .map_or(Err(InvalidPacketKind), |e| Ok(*e))
    }
}

impl Display for PacketKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}
#[derive(PartialEq)]
enum Stage {
    Waiting,
    Ready,
    Receiving,
}

/// Sends a file using the ZMODEM file transfer protocol.
pub fn write<P, F>(
    port: &mut P,
    file: &mut F,
    filename: &str,
    filesize: Option<u32>,
) -> io::Result<()>
where
    P: Read + Write,
    F: Read + Seek,
{
    let mut stage = Stage::Waiting;

    ZRQINIT_HEADER.write(port)?;
    loop {
        match read_zpad(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => continue,
            Err(err) => return Err(err),
            _ => (),
        }

        let frame = match FrameHeader::read(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                ZNAK_HEADER.write(port)?;
                continue;
            }
            Err(err) => return Err(err),
            Ok(frame) => frame,
        };

        match frame.frame_type() {
            FrameKind::ZRINIT => match stage {
                Stage::Waiting => {
                    // FIXME: Remove heap allocation:
                    let mut buf = vec![];

                    ZFILE_HEADER.write(port)?;
                    buf.extend_from_slice(filename.as_bytes());
                    buf.push(b'\0');
                    if let Some(size) = filesize {
                        buf.extend_from_slice(size.to_string().as_bytes());
                    }
                    buf.push(b'\0');
                    write_subpacket(port, Encoding::ZBIN32, PacketKind::ZCRCW, &buf)?;
                    stage = Stage::Ready;
                }
                Stage::Ready => (),
                Stage::Receiving => ZFIN_HEADER.write(port)?,
            },
            FrameKind::ZRPOS | FrameKind::ZACK => {
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
pub fn read<P, F>(port: &mut P, file: &mut F) -> io::Result<usize>
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

        let frame = match FrameHeader::read(port) {
            Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                ZNAK_HEADER.write(port)?;
                continue;
            }
            Err(err) => return Err(err),
            Ok(frame) => frame,
        };

        match frame.frame_type() {
            FrameKind::ZFILE => match stage {
                Stage::Waiting | Stage::Ready => {
                    assert_eq!(count, 0);
                    // FIXME: Remove heap allocation:
                    let mut buf = Vec::new();
                    match read_subpacket(port, frame.encoding(), &mut buf).map(|_| ()) {
                        Err(ref err) if err.kind() == ErrorKind::InvalidData => {
                            ZNAK_HEADER.write(port)
                        }
                        Err(err) => Err(err),
                        _ => ZRPOS_HEADER.with_count(0).write(port),
                    }?;
                    stage = Stage::Ready;
                }
                Stage::Receiving => (),
            },
            FrameKind::ZDATA => match stage {
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
            FrameKind::ZEOF if stage == Stage::Receiving => {
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
            FrameKind::ZFIN if stage == Stage::Receiving => {
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

/// Writes a ZDATA
fn write_zdata<P, F>(port: &mut P, file: &mut F, header: &FrameHeader) -> io::Result<()>
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
        write_subpacket(port, Encoding::ZBIN32, PacketKind::ZCRCG, &data[..count])?;
        offset += count as u32;

        count = file.read(&mut data)?;
        if count < SUBPACKET_SIZE {
            break;
        }
    }
    write_subpacket(port, Encoding::ZBIN32, PacketKind::ZCRCW, &data[..count])?;

    Ok(())
}

/// Reads a ZDATA packet
fn read_zdata<P, F>(encoding: u8, count: &mut u32, port: &mut P, file: &mut F) -> io::Result<()>
where
    P: Write + Read,
    F: Write,
{
    // FIXME: Remove heap allocation:
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
            PacketKind::ZCRCW => {
                ZACK_HEADER.with_count(*count).write(port)?;
                return Ok(());
            }
            PacketKind::ZCRCE => return Ok(()),
            PacketKind::ZCRCQ => {
                ZACK_HEADER.with_count(*count).write(port)?;
            }
            PacketKind::ZCRCG => log::debug!("ZCRCG"),
        }
    }
}

/// Skips (ZPAD, [ZPAD,] ZDLE) sequence.
fn read_zpad<P>(port: &mut P) -> io::Result<()>
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
// FIXME: Remove heap allocation
fn read_subpacket<P>(port: &mut P, encoding: Encoding, buf: &mut Vec<u8>) -> io::Result<PacketKind>
where
    P: Read,
{
    let result;

    loop {
        let byte = read_byte(port)?;
        if byte == ZDLE {
            let byte = read_byte(port)?;
            if let Ok(sp_type) = PacketKind::try_from(byte) {
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
    let mut crc = [0u8; 4];
    for b in crc.iter_mut().take(crc_len) {
        *b = read_byte_unescaped(port)?;
    }
    check_crc(buf, &crc[..crc_len], encoding)?;

    // Pop ZCRC
    buf.pop().unwrap();
    Ok(result)
}

fn write_subpacket<P>(
    port: &mut P,
    encoding: Encoding,
    subpacket_type: PacketKind,
    data: &[u8],
) -> io::Result<()>
where
    P: Write,
{
    let subpacket_type = subpacket_type as u8;

    // FIXME: Remove heap allocation:
    let mut esc_data = vec![];
    escape_array(data, &mut esc_data);
    port.write_all(&esc_data)?;
    // FIXME: Remove heap allocation:
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

fn check_crc(data: &[u8], crc: &[u8], encoding: Encoding) -> io::Result<()> {
    let mut crc2 = [0u8; 4];
    let crc2_len = make_crc(data, &mut crc2, encoding);

    if *crc != crc2[..crc2_len] {
        log::error!("ZCRC mismatch: {:?} != {:?}", crc, &crc2[..crc2_len]);
        return Err(ErrorKind::InvalidData.into());
    }

    Ok(())
}

fn make_crc(data: &[u8], out: &mut [u8], encoding: Encoding) -> usize {
    match encoding {
        Encoding::ZBIN32 => {
            let crc = CRC32.checksum(data).to_le_bytes();
            out[..4].copy_from_slice(&crc[..4]);
            4
        }
        _ => {
            let crc = CRC16.checksum(data).to_be_bytes();
            out[..2].copy_from_slice(&crc[..2]);
            2
        }
    }
}

fn read_byte_unescaped<P>(port: &mut P) -> io::Result<u8>
where
    P: io::Read,
{
    let b = read_byte(port)?;
    Ok(if b == ZDLE {
        unescape(read_byte(port)?)
    } else {
        b
    })
}

fn read_byte<P>(port: &mut P) -> io::Result<u8>
where
    P: io::Read,
{
    let mut buf = [0; 1];
    port.read_exact(&mut buf).map(|_| buf[0])
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

// FIXME: Remove heap allocation:
pub fn escape_array(src: &[u8], dst: &mut Vec<u8>) {
    for value in src {
        let escaped = escape(*value);
        if escaped != *value {
            dst.push(ZDLE);
        }
        dst.push(escaped);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        read_subpacket, read_zpad, write_subpacket, Encoding, FrameHeader, FrameKind, PacketKind,
        XON, ZDLE, ZPAD,
    };

    #[rstest::rstest]
    #[case(Encoding::ZBIN, FrameKind::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(Encoding::ZBIN32, FrameKind::ZRQINIT, &[ZPAD, ZDLE, Encoding::ZBIN32 as u8, 0, 0, 0, 0, 0, 29, 247, 34, 198])]
    pub fn test_header(
        #[case] encoding: Encoding,
        #[case] frame_type: FrameKind,
        #[case] expected: &[u8],
    ) {
        let header = FrameHeader::new(encoding, frame_type).with_flags(&[0; 4]);
        let mut port = vec![];
        header.write(&mut port).unwrap();
        assert_eq!(port, expected);
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, FrameKind::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZDLE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148])]
    #[case(Encoding::ZHEX, FrameKind::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZPAD, ZDLE, Encoding::ZHEX as u8, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'1', b'0', b'1', 54, 50, 57, 52, b'\r', b'\n', XON])]
    pub fn test_header_with_flags(
        #[case] encoding: Encoding,
        #[case] frame_type: FrameKind,
        #[case] flags: &[u8; 4],
        #[case] expected: &[u8],
    ) {
        let header = FrameHeader::new(encoding, frame_type).with_flags(flags);
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
    #[case(&[Encoding::ZHEX as u8, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'], &FrameHeader::new(Encoding::ZHEX, FrameKind::ZRINIT).with_flags(&[0x1, 0x2, 0x3, 0x4]))]
    #[case(&[Encoding::ZBIN as u8, FrameKind::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb], &FrameHeader::new(Encoding::ZBIN, FrameKind::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN32 as u8, FrameKind::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a], &FrameHeader::new(Encoding::ZBIN32, FrameKind::ZRINIT).with_flags(&[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN as u8, FrameKind::ZRINIT as u8, 0xa, ZDLE, b'l', 0xd, ZDLE, b'm', 0x5e, 0x6f], &FrameHeader::new(Encoding::ZBIN, FrameKind::ZRINIT).with_flags(&[0xa, 0x7f, 0xd, 0xff]))]
    pub fn test_header_read(#[case] input: &[u8], #[case] expected: &FrameHeader) {
        let input = input.to_vec();
        assert_eq!(
            &mut FrameHeader::read(&mut input.as_slice()).unwrap(),
            expected
        );
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, PacketKind::ZCRCE, &[])]
    #[case(Encoding::ZBIN, PacketKind::ZCRCW, &[0x00])]
    #[case(Encoding::ZBIN32, PacketKind::ZCRCQ, &[0, 1, 2, 3, 4, 0x60, 0x60])]
    pub fn test_write_read_subpacket(
        #[case] encoding: Encoding,
        #[case] subpacket_type: PacketKind,
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
