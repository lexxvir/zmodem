// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM transfer protocol frame

use consts::*;
use core::{convert::TryFrom, mem::size_of, slice::from_raw_parts};
use hex::*;
use proto;
use std::fmt::{self, Display};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[repr(u8)]
#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq)]
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
#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    encoding: Encoding,
    frame_type: Type,
    flags: [u8; 4],
}

impl From<&Header> for &[u8] {
    fn from(value: &Header) -> Self {
        // SAFETY: out-of-boundary is not possible, given that the size constraint
        // exists in the struct definition.
        unsafe { from_raw_parts((value as *const Header) as *const u8, size_of::<Header>()) }
    }
}

impl Header {
    pub fn new(encoding: Encoding, frame_type: Type) -> Header {
        Header {
            encoding,
            frame_type,
            flags: [0; 4],
        }
    }

    pub fn flags<'b>(&'b mut self, flags: &[u8; 4]) -> &'b mut Header {
        self.flags = *flags;
        self
    }

    pub fn count(&mut self, count: u32) -> &mut Header {
        self.flags = [
            count as u8,
            (count >> 8) as u8,
            (count >> 16) as u8,
            (count >> 24) as u8,
        ];
        self
    }

    pub fn get_count(&self) -> u32 {
        (self.flags[3] as u32) << 24
            | (self.flags[2] as u32) << 16
            | (self.flags[1] as u32) << 8
            | (self.flags[0] as u32)
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.push(ZPAD);
        if self.encoding == Encoding::ZHEX {
            out.push(ZPAD);
        }

        out.push(ZLDE);
        out.extend_from_slice(self.into());

        // FIXME: Offsets are defined with magic numbers. Check that the offsets
        // are indeed correct and clarify their purpose.
        out.append(&mut match self.encoding {
            Encoding::ZBIN32 => CRC32.checksum(&out[3..]).to_le_bytes().to_vec(),
            Encoding::ZHEX => CRC16.checksum(&out[4..]).to_be_bytes().to_vec(),
            _ => CRC16.checksum(&out[3..]).to_be_bytes().to_vec(),
        });

        if self.encoding == Encoding::ZHEX {
            let hex = out.drain(4..).collect::<Vec<u8>>().to_hex();
            out.extend_from_slice(hex.as_bytes());
        }

        let tmp = out.drain(3..).collect::<Vec<_>>();
        let mut tmp2 = Vec::new();
        proto::escape_buf(&tmp, &mut tmp2);
        out.extend_from_slice(&tmp2);

        if self.encoding == Encoding::ZHEX {
            out.extend_from_slice(b"\r\n");

            if self.frame_type != Type::ZACK && self.frame_type != Type::ZFIN {
                out.push(XON);
            }
        }

        out
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

#[test]
fn test_frame() {
    assert_eq!(
        Header::new(Encoding::ZBIN, Type::ZRQINIT).build(),
        vec![ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0]
    );

    assert_eq!(
        Header::new(Encoding::ZBIN32, Type::ZRQINIT).build(),
        vec![
            ZPAD,
            ZLDE,
            Encoding::ZBIN32 as u8,
            0,
            0,
            0,
            0,
            0,
            29,
            247,
            34,
            198
        ]
    );

    assert_eq!(
        Header::new(Encoding::ZBIN, Type::ZRQINIT)
            .flags(&[1; 4])
            .build(),
        vec![ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148]
    );

    assert_eq!(
        Header::new(Encoding::ZBIN, Type::ZRQINIT)
            .flags(&[1; 4])
            .build(),
        vec![ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148]
    );

    assert_eq!(
        Header::new(Encoding::ZHEX, Type::ZRQINIT)
            .flags(&[1; 4])
            .build(),
        vec![
            ZPAD,
            ZPAD,
            ZLDE,
            Encoding::ZHEX as u8,
            b'0',
            b'0',
            b'0',
            b'1',
            b'0',
            b'1',
            b'0',
            b'1',
            b'0',
            b'1',
            54,
            50,
            57,
            52,
            b'\r',
            b'\n',
            XON
        ]
    );
}
