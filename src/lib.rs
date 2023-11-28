// SPDX-License-Identifier: MIT OR Apache-2.0

#[macro_use]
extern crate log;

extern crate core;
extern crate crc;
extern crate hex;
extern crate zerocopy;

mod consts;
mod frame;
mod port;
mod proto;

pub mod recv;
pub mod send;

use consts::*;

pub fn is_u8_escaped(byte: u8) -> bool {
    !matches!(byte, ZCRCE | ZCRCG | ZCRCQ | ZCRCW)
}

pub fn escape_u8(value: u8) -> Option<[u8; 2]> {
    Some(match value {
        0xFF => [ZLDE, ESC_FF],
        0x7F => [ZLDE, ESC_7F],
        0x10 | 0x90 | 0x11 | 0x91 | 0x13 | 0x93 => [ZLDE, value ^ 0x40],
        ZLDE => [ZLDE, ZLDEE],
        _ => return None,
    })
}

pub fn escape_u8_array(src: &[u8], dst: &mut Vec<u8>) {
    for value in src {
        if let Some(value) = escape_u8(*value) {
            dst.extend_from_slice(&value);
        } else {
            dst.push(*value);
        }
    }
}

pub fn unescape_u8(escaped_byte: u8) -> u8 {
    match escaped_byte {
        ESC_FF => 0xFF,
        ESC_7F => 0x7F,
        x => {
            if x & 0x60 != 0 {
                x ^ 0x40
            } else {
                x
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::*;
    use crate::frame::*;
    use crate::proto::*;

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(Encoding::ZBIN32, Type::ZRQINIT, &[ZPAD, ZLDE, Encoding::ZBIN32 as u8, 0, 0, 0, 0, 0, 29, 247, 34, 198])]
    pub fn test_header(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type, &[0; 4]);
        let frame = Frame::new(&header);
        assert_eq!(frame.0, expected);
    }

    #[rstest::rstest]
    #[case(Encoding::ZBIN, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZLDE, Encoding::ZBIN as u8, 0, 1, 1, 1, 1, 98, 148])]
    #[case(Encoding::ZHEX, Type::ZRQINIT, &[1, 1, 1, 1], &[ZPAD, ZPAD, ZLDE, Encoding::ZHEX as u8, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'1', b'0', b'1', 54, 50, 57, 52, b'\r', b'\n', XON])]
    pub fn test_header_with_flags(
        #[case] encoding: Encoding,
        #[case] frame_type: Type,
        #[case] flags: &[u8; 4],
        #[case] expected: &[u8],
    ) {
        let header = Header::new(encoding, frame_type, flags);
        let frame = Frame::new(&header);
        assert_eq!(frame.0, expected);
    }

    #[rstest::rstest]
    #[case(&[ZPAD, ZLDE], Ok(true))]
    #[case(&[ZPAD, ZPAD, ZLDE], Ok(true))]
    #[case(&[ZLDE], Ok(true))]
    #[case(&[], Err(std::io::ErrorKind::InvalidData.into()))]
    #[case(&[0; 100], Ok(false))]
    pub fn test_try_skip_zpad(#[case] data: &[u8], #[case] expected: std::io::Result<bool>) {
        let data = data.to_vec();
        assert_eq!(
            try_skip_zpad(&mut data.as_slice()).is_err(),
            expected.is_err()
        );
    }

    #[rstest::rstest]
    #[case(&[0; 32], &[0; 32], &[0; 32])]
    #[case(&[ZLDE, b'm', ZLDE, b'l', ZLDE, 0x6f], &[0; 3], &[0xff, 0x7f, 0x2f])]
    #[case(&[ZLDE, b'm', 0, 2, ZLDE, b'l'], &[0; 4], &[0xff, 0, 2, 0x7f])]
    pub fn test_read_exact_unescaped(
        #[case] input: &[u8],
        #[case] output: &[u8],
        #[case] expected: &[u8],
    ) {
        let mut output = output.to_vec();
        read_exact_unescaped(&input[..], &mut output).unwrap();
        assert_eq!(&output, expected);
    }

    #[rstest::rstest]
    #[case(&[Encoding::ZHEX as u8, b'0', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'a', b'7', b'5', b'2'], &Header::new(Encoding::ZHEX, Type::ZRINIT, &[0x1, 0x2, 0x3, 0x4]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0xa6, 0xcb], &Header::new(Encoding::ZBIN, Type::ZRINIT, &[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN32 as u8, Type::ZRINIT as u8, 0xa, 0xb, 0xc, 0xd, 0x99, 0xe2, 0xae, 0x4a], &Header::new(Encoding::ZBIN32, Type::ZRINIT, &[0xa, 0xb, 0xc, 0xd]))]
    #[case(&[Encoding::ZBIN as u8, Type::ZRINIT as u8, 0xa, ZLDE, b'l', 0xd, ZLDE, b'm', 0x5e, 0x6f], &Header::new(Encoding::ZBIN, Type::ZRINIT, &[0xa, 0x7f, 0xd, 0xff]))]
    pub fn test_parse_header(#[case] input: &[u8], #[case] expected: &Header) {
        assert_eq!(&mut parse_header(&input[..]).unwrap().unwrap(), expected);
    }

    #[test]
    fn test_parse_header_none() {
        let frame = Type::ZRINIT;
        let i = [0xaa, frame as u8, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf];
        assert_eq!(parse_header(&i[..]).unwrap_or(None), None);
    }

    #[test]
    fn test_recv_zlde_frame() {
        let i = vec![ZLDE, ZCRCE, 237, 174];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCE)
        );
        assert_eq!(&v[..], []);

        let i = vec![ZLDE, 0x00, ZLDE, ZCRCW, 221, 205];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCW)
        );
        assert_eq!(&v[..], [0x00]);

        let i = vec![
            0, 1, 2, 3, 4, ZLDE, 0x60, ZLDE, 0x60, ZLDE, ZCRCQ, 85, 114, 241, 70,
        ];
        let mut v = vec![];
        assert_eq!(
            recv_zlde_frame(Encoding::ZBIN32, &mut i.as_slice(), &mut v).unwrap(),
            Some(ZCRCQ)
        );
        assert_eq!(&v[..], [0, 1, 2, 3, 4, 0x20, 0x20]);
    }
}
