use crc32::{Crc, CRC_16_XMODEM, CRC_32_ISO_HDLC};

const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub fn get_crc16(buf: &[u8], maybe_zcrc: Option<u8>) -> [u8; 2] {
    let mut digest = CRC16.digest();

    digest.update(buf);

    if let Some(zcrc) = maybe_zcrc {
        digest.update(&[zcrc]);
    }

    let crc = digest.finalize();
    [(crc >> 8) as u8, (crc & 0xff) as u8]
}

pub fn get_crc32(buf: &[u8], maybe_zcrc: Option<u8>) -> [u8; 4] {
    let mut digest = CRC32.digest();

    digest.update(buf);

    if let Some(zcrc) = maybe_zcrc {
        digest.update(&[zcrc]);
    }

    let crc = digest.finalize();
    [
        (crc & 0xff) as u8,
        (crc >> 8) as u8,
        (crc >> 16) as u8,
        (crc >> 24) as u8,
    ]
}
