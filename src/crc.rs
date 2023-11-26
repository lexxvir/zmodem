use crc32::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};

pub const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
pub const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub fn get_crc32(buf: &[u8], maybe_zcrc: Option<u8>) -> [u8; 4] {
    let mut digest = CRC32.digest();

    digest.update(buf);

    if let Some(zcrc) = maybe_zcrc {
        digest.update(&[zcrc]);
    }

    // Assuming little-endian byte order, given that ZMODEM used to work on
    // VAX, which was a little-endian computer architecture:
    digest.finalize().to_le_bytes()
}
