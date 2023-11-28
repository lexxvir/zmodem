// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::frame::{Encoding, Header, Type};
use crc::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub const ZACK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZACK, &[0; 4]);
pub const ZDATA_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZDATA, &[0; 4]);
pub const ZEOF_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZEOF, &[0; 4]);
pub const ZFILE_HEADER: Header = Header::new(Encoding::ZBIN32, Type::ZFILE, &[0, 0, 0, 0x23]);
pub const ZFIN_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZFIN, &[0; 4]);
pub const ZNAK_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZNAK, &[0; 4]);
pub const ZRINIT_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRINIT, &[0, 0, 0, 0x23]);
pub const ZRPOS_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRPOS, &[0; 4]);
pub const ZRQINIT_HEADER: Header = Header::new(Encoding::ZHEX, Type::ZRQINIT, &[0, 0, 0, 0x23]);

pub const ZPAD: u8 = b'*';
pub const ZLDE: u8 = 0x18;
pub const ZLDEE: u8 = 0x58;

pub const ESC_FF: u8 = b'm';
pub const ESC_7F: u8 = b'l';

/* ZDLE sequences */
pub const ZCRCE: u8 = b'h'; /* CRC next, frame ends, header packet follows */
pub const ZCRCG: u8 = b'i'; /* CRC next, frame continues nonstop */
pub const ZCRCQ: u8 = b'j'; /* CRC next, frame continues, ZACK expected */
pub const ZCRCW: u8 = b'k'; /* CRC next, ZACK expected, end of frame */

pub const XON: u8 = 0x11;
