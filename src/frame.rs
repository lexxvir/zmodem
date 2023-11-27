// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM transfer protocol frame

use crate::consts::*;
use crate::proto;
use crate::zerocopy::AsBytes;
use core::convert::TryFrom;
use hex::*;
use std::fmt::{self, Display};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(AsBytes, Clone, Copy, Debug, EnumIter, PartialEq)]
/// The ZMODEM frame type
pub enum Encoding {
    ZBIN = 0x41,
    ZHEX = 0x42,
    ZBIN32 = 0x43,
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidEncoding;

impl TryFrom<u8> for Encoding {
    type Error = InvalidEncoding;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if let Some(e) = Encoding::iter().find(|e| value == *e as u8) {
            Ok(e)
        } else {
            Err(InvalidEncoding)
        }
    }
}

impl Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[derive(AsBytes, Clone, Copy, Debug, EnumIter, PartialEq)]
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

#[derive(Clone, Copy, Debug)]
pub struct InvalidType;

impl TryFrom<u8> for Type {
    type Error = InvalidType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if let Some(e) = Type::iter().find(|e| value == *e as u8) {
            Ok(e)
        } else {
            Err(InvalidType)
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

#[repr(C)]
#[allow(dead_code)]
union Descriptor {
    flags: [u8; 4],
    count: u32,
}

#[repr(C)]
#[derive(AsBytes, Clone, Copy, Debug, PartialEq)]
pub struct Header {
    encoding: Encoding,
    frame_type: Type,
    flags: [u8; 4],
}

impl Header {
    pub fn new(encoding: Encoding, frame_type: Type) -> Header {
        Header {
            encoding,
            frame_type,
            flags: [0; 4],
        }
    }

    pub fn flags(&mut self, flags: &[u8; 4]) -> Header {
        self.flags = *flags;
        *self
    }

    pub fn count(&mut self, count: u32) -> Header {
        self.flags = count.to_le_bytes();
        *self
    }

    pub fn get_count(&self) -> u32 {
        u32::from_le_bytes(self.flags)
    }

    pub fn frame_type(&self) -> Type {
        self.frame_type
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:8} {}", self.encoding, self.frame_type)
    }
}

pub fn new_frame(header: &Header, out: &mut Vec<u8>) {
    out.push(ZPAD);
    if header.encoding == Encoding::ZHEX {
        out.push(ZPAD);
    }

    out.push(ZLDE);
    out.extend_from_slice(header.as_bytes());

    // FIXME: Offsets are defined with magic numbers. Check that the offsets
    // are indeed correct and clarify their purpose.
    out.append(&mut match header.encoding {
        Encoding::ZBIN32 => CRC32.checksum(&out[3..]).to_le_bytes().to_vec(),
        Encoding::ZHEX => CRC16.checksum(&out[4..]).to_be_bytes().to_vec(),
        _ => CRC16.checksum(&out[3..]).to_be_bytes().to_vec(),
    });

    if header.encoding == Encoding::ZHEX {
        let hex = out.drain(4..).collect::<Vec<u8>>().to_hex();
        out.extend_from_slice(hex.as_bytes());
    }

    let tmp = out.drain(3..).collect::<Vec<_>>();
    let mut tmp2 = Vec::new();
    proto::escape_buf(&tmp, &mut tmp2);
    out.extend_from_slice(&tmp2);

    if header.encoding == Encoding::ZHEX {
        out.extend_from_slice(b"\r\n");

        if header.frame_type != Type::ZACK && header.frame_type != Type::ZFIN {
            out.push(XON);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::frame::*;

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(Encoding::ZBIN32, Type::ZRQINIT, &[ZPAD, ZLDE, Encoding::ZBIN32 as u8, 0, 0, 0, 0, 0, 29, 247, 34, 198])]
    fn test_header(#[case] encoding: Encoding, #[case] frame_type: Type, #[case] expected: &[u8]) {
        let header = Header::new(encoding, frame_type);

        let mut packet = vec![];
        new_frame(&header, &mut packet);

        assert_eq!(packet, expected);
    }
    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148])]
    #[case(Encoding::ZHEX, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZPAD, ZLDE, Encoding::ZHEX as u8, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'1', b'0', b'1', 54, 50, 57, 52, b'\r', b'\n', XON])]
    fn test_header_with_flags(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] flags: &[u8; 4],
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type).flags(flags);

        let mut packet = vec![];
        new_frame(&header, &mut packet);

        assert_eq!(packet, expected);
    }
}
