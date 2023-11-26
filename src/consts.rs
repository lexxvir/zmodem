// SPDX-License-Identifier: MIT OR Apache-2.0

use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const ZPAD: u8 = b'*';
pub const ZLDE: u8 = 0x18;
pub const ZLDEE: u8 = 0x58;
pub const ZBIN: u8 = b'A'; // 0x41
pub const ZHEX: u8 = b'B'; // 0x42
pub const ZBIN32: u8 = b'C'; // 0x43

pub const ESC_FF: u8 = b'm';
pub const ESC_7F: u8 = b'l';

/* ZDLE sequences */
pub const ZCRCE: u8 = b'h'; /* CRC next, frame ends, header packet follows */
pub const ZCRCG: u8 = b'i'; /* CRC next, frame continues nonstop */
pub const ZCRCQ: u8 = b'j'; /* CRC next, frame continues, ZACK expected */
pub const ZCRCW: u8 = b'k'; /* CRC next, ZACK expected, end of frame */

pub const XON: u8 = 0x11;
