use crc32::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
