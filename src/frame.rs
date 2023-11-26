// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZMODEM transfer protocol frame

use consts::*;
use core::convert::TryFrom;
use hex::*;
use proto;
use std::fmt::{self, Display};
use std::io::ErrorKind;

pub const FRAME_TYPES: u8 = 20;

#[repr(u8)]
#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

impl TryFrom<u8> for Type {
    // TODO: create a frame error type for catching unexpected traffic coming
    // from the serial port, and use it here.
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value >= FRAME_TYPES {
            return Err(ErrorKind::InvalidInput.into());
        }

        // SAFETY: conversion is safe as the range is checked and the enum is
        // not sparse.
        unsafe { Ok(core::mem::transmute::<u8, Type>(value)) }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#02x}", *self as u8)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    encoding: u8,
    frame_type: Type,
    flags: [u8; 4],
}

impl Frame {
    pub fn new(encoding: u8, frame_type: Type) -> Frame {
        Frame {
            encoding,
            frame_type,
            flags: [0; 4],
        }
    }

    pub fn flags<'b>(&'b mut self, flags: &[u8; 4]) -> &'b mut Frame {
        self.flags = *flags;
        self
    }

    pub fn count(&mut self, count: u32) -> &mut Frame {
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
        if self.encoding == ZHEX {
            out.push(ZPAD);
        }

        out.push(ZLDE);
        out.push(self.encoding);
        out.push(self.frame_type as u8);
        out.extend_from_slice(&self.flags);

        // FIXME: Offsets are defined with magic numbers. Check that the offsets
        // are indeed correct and clarify their purpose.
        out.append(&mut match self.encoding {
            ZBIN32 => CRC32.checksum(&out[3..]).to_le_bytes().to_vec(),
            ZHEX => CRC16.checksum(&out[4..]).to_be_bytes().to_vec(),
            _ => CRC16.checksum(&out[3..]).to_be_bytes().to_vec(),
        });

        if self.encoding == ZHEX {
            let hex = out.drain(4..).collect::<Vec<u8>>().to_hex();
            out.extend_from_slice(hex.as_bytes());
        }

        let tmp = out.drain(3..).collect::<Vec<_>>();
        let mut tmp2 = Vec::new();
        proto::escape_buf(&tmp, &mut tmp2);
        out.extend_from_slice(&tmp2);

        if self.encoding == ZHEX {
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

    pub fn encoding(&self) -> u8 {
        self.encoding
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hdr = match self.encoding {
            ZHEX => "ZHEX",
            ZBIN => "ZBIN",
            ZBIN32 => "ZBIN32",
            _ => "???",
        };

        write!(f, "{:8} {}", hdr, self.frame_type)
    }
}

#[test]
fn test_frame() {
    assert_eq!(
        Frame::new(ZBIN, Type::ZRQINIT).build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 0, 0, 0, 0, 0, 0]
    );

    assert_eq!(
        Frame::new(ZBIN32, Type::ZRQINIT).build(),
        vec![ZPAD, ZLDE, ZBIN32, 0, 0, 0, 0, 0, 29, 247, 34, 198]
    );

    assert_eq!(
        Frame::new(ZBIN, Type::ZRQINIT).flags(&[1; 4]).build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 1, 1, 1, 1, 98, 148]
    );

    assert_eq!(
        Frame::new(ZBIN, Type::ZRQINIT).flags(&[1; 4]).build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 1, 1, 1, 1, 98, 148]
    );

    assert_eq!(
        Frame::new(ZHEX, Type::ZRQINIT).flags(&[1; 4]).build(),
        vec![
            ZPAD, ZPAD, ZLDE, ZHEX, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'1', b'0', b'1', 54,
            50, 57, 52, b'\r', b'\n', XON
        ]
    );
}
