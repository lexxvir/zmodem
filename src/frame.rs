// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM transfer protocol frame

use crate::{escape_array, CRC16, CRC32, XON, ZDLE, ZPAD};
use core::convert::TryFrom;
use std::fmt::{self, Display};
use zerocopy::AsBytes;

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(AsBytes, Clone, Copy, Debug, PartialEq)]
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
#[derive(AsBytes, Clone, Copy, Debug, PartialEq)]
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

#[repr(C)]
#[derive(AsBytes, Clone, Copy, Debug, PartialEq)]
pub struct Header {
    encoding: Encoding,
    frame_type: Type,
    flags: [u8; 4],
}

impl Header {
    pub const fn new(encoding: Encoding, frame_type: Type, flags: &[u8; 4]) -> Header {
        Header {
            encoding,
            frame_type,
            flags: *flags,
        }
    }

    pub const fn with_count(&self, count: u32) -> Self {
        Header {
            encoding: self.encoding,
            frame_type: self.frame_type,
            flags: count.to_le_bytes(),
        }
    }

    /// Returns encoded size of the header when it is streamed to the serial link.
    pub const fn encoded_size(encoding: Encoding) -> usize {
        match encoding {
            Encoding::ZBIN => core::mem::size_of::<Header>() + 2,
            Encoding::ZBIN32 => core::mem::size_of::<Header>() + 4,
            Encoding::ZHEX => (core::mem::size_of::<Header>() + 2) * 2 - 1
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
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:8} {}", self.encoding, self.frame_type)
    }
}

#[allow(dead_code)]
pub struct Frame(pub Vec<u8>);

impl Frame {
    #[allow(dead_code)]
    pub fn new(header: &Header) -> Self {
        let mut out = vec![];

        out.push(ZPAD);
        if header.encoding == Encoding::ZHEX {
            out.push(ZPAD);
        }

        out.push(ZDLE);
        out.extend_from_slice(header.as_bytes());

        // Skips ZPAD and encoding:
        match header.encoding {
            Encoding::ZBIN32 => out.extend_from_slice(&CRC32.checksum(&out[3..]).to_le_bytes()),
            Encoding::ZHEX => out.extend_from_slice(&CRC16.checksum(&out[4..]).to_be_bytes()),
            _ => out.extend_from_slice(&CRC16.checksum(&out[3..]).to_be_bytes()),
        };

        // Skips ZPAD and encoding:
        if header.encoding == Encoding::ZHEX {
            let hex = hex::encode(&out[4..]);
            out.truncate(4);
            out.extend_from_slice(hex.as_bytes());
        }

        let mut escaped = vec![];
        escape_array(&out[3..], &mut escaped);
        out.truncate(3);
        out.extend_from_slice(escaped.as_bytes());

        if header.encoding == Encoding::ZHEX {
            // Add trailing CRLF for ZHEX transfer:
            out.extend_from_slice(b"\r\n");

            if header.frame_type != Type::ZACK && header.frame_type != Type::ZFIN {
                out.push(XON);
            }
        }

        Self(out)
    }
}
