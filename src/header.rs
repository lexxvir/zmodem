// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM transfer protocol frame

use crate::{escape_array, read_exact_unescaped, CRC16, CRC32, XON, ZDLE, ZPAD};
use bitflags::bitflags;
use core::convert::TryFrom;
use hex::FromHex;
use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use tinyvec::array_vec;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Header {
    encoding: Encoding,
    frame_type: Type,
    flags: [u8; 4],
}

impl Header {
    pub const fn new(encoding: Encoding, frame_type: Type) -> Header {
        Header {
            encoding,
            frame_type,
            flags: [0; 4],
        }
    }

    pub const fn with_count(&self, count: u32) -> Self {
        Header {
            encoding: self.encoding,
            frame_type: self.frame_type,
            flags: count.to_le_bytes(),
        }
    }

    pub const fn with_flags(&self, flags: &[u8; 4]) -> Self {
        Header {
            encoding: self.encoding,
            frame_type: self.frame_type,
            flags: *flags,
        }
    }

    /// Returns encoded size of the header when it is streamed to the serial link.
    pub const fn encoded_size(encoding: Encoding) -> usize {
        match encoding {
            Encoding::ZBIN => core::mem::size_of::<Header>() + 2,
            Encoding::ZBIN32 => core::mem::size_of::<Header>() + 4,
            // Encoding is stored as a single byte also for ZHEX, thus the
            // subtraction:
            Encoding::ZHEX => (core::mem::size_of::<Header>() + 2) * 2 - 1,
        }
    }

    pub const fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub const fn frame_type(&self) -> Type {
        self.frame_type
    }

    pub const fn count(&self) -> u32 {
        u32::from_le_bytes(self.flags)
    }

    pub fn read<R>(mut r: R) -> io::Result<Option<Header>>
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

        let header = Header::new(encoding, ft).with_flags(&[v[1], v[2], v[3], v[4]]);
        log::trace!("FRAME {}", header);
        Ok(Some(header))
    }

    pub fn write<P>(&self, port: &mut P) -> io::Result<()>
    where
        P: Write,
    {
        let mut out = array_vec!([u8; Header::encoded_size(Encoding::ZHEX) + 6]);

        out.push(ZPAD);
        if self.encoding == Encoding::ZHEX {
            out.push(ZPAD);
        }

        out.push(ZDLE);
        out.push(self.encoding as u8);
        out.push(self.frame_type as u8);
        out.extend_from_slice(&self.flags);

        // Skips ZPAD and encoding:
        match self.encoding {
            Encoding::ZBIN32 => out.extend_from_slice(&CRC32.checksum(&out[3..]).to_le_bytes()),
            Encoding::ZHEX => out.extend_from_slice(&CRC16.checksum(&out[4..]).to_be_bytes()),
            Encoding::ZBIN => out.extend_from_slice(&CRC16.checksum(&out[3..]).to_be_bytes()),
        };

        // Skips ZPAD and encoding:
        if self.encoding == Encoding::ZHEX {
            let hex = hex::encode(&out[4..]);
            out.truncate(4);
            out.extend_from_slice(hex.as_bytes());
        }

        let mut escaped = vec![];
        escape_array(&out[3..], &mut escaped);
        out.truncate(3);
        out.extend_from_slice(&escaped);

        if self.encoding == Encoding::ZHEX {
            // Add trailing CRLF for ZHEX transfer:
            out.extend_from_slice(b"\r\n");

            if self.frame_type != Type::ZACK && self.frame_type != Type::ZFIN {
                out.push(XON);
            }
        }

        port.write_all(&out)
    }
}

impl fmt::Display for Header {
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
pub enum Type {
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

const TYPES: &[Type] = &[
    Type::ZRQINIT,
    Type::ZRINIT,
    Type::ZSINIT,
    Type::ZACK,
    Type::ZFILE,
    Type::ZSKIP,
    Type::ZNAK,
    Type::ZABORT,
    Type::ZFIN,
    Type::ZRPOS,
    Type::ZDATA,
    Type::ZEOF,
    Type::ZFERR,
    Type::ZCRC,
    Type::ZCHALLENGE,
    Type::ZCOMPL,
    Type::ZCAN,
    Type::ZFREECNT,
    Type::ZCOMMAND,
    Type::ZSTDERR,
];

#[derive(Clone, Copy, Debug)]
pub struct InvalidType;

impl TryFrom<u8> for Type {
    type Error = InvalidType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        TYPES
            .iter()
            .find(|t| value == **t as u8)
            .map_or(Err(InvalidType), |t| Ok(*t))
    }
}

impl Display for Type {
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
