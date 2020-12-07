use std::fmt;
use consts::*;
use crc;
use hex::*;
use proto;

#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    header: u8,
    ftype: u8,
    flags: [u8; 4],
}

impl Frame {
    pub fn new(header: u8, ftype: u8) -> Frame {
        Frame {
            header,
            ftype,
            flags: [0; 4],
        }
    }

    pub fn flags<'b>(&'b mut self, flags: &[u8; 4]) -> &'b mut Frame {
        self.flags = *flags;
        self
    }

    pub fn count<'b>(&'b mut self, count: u32) -> &'b mut Frame {
        self.flags = [
               (count >>  0) as u8,
               (count >>  8) as u8,
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
        if self.header == ZHEX {
            out.push(ZPAD);
        }

        out.push(ZLDE);
        out.push(self.header);
        out.push(self.ftype);
        out.extend_from_slice(&self.flags);

        let mut crc = get_crc(self.header, &out);
        out.append(&mut crc);

        if self.header == ZHEX {
            let hex = out.drain(4..).collect::<Vec<u8>>().to_hex();
            out.extend_from_slice(&hex.as_bytes());
        }

        let tmp = out.drain(3..).collect::<Vec<_>>();
        let mut tmp2 = Vec::new();
        proto::escape_buf(&tmp, &mut tmp2);
        out.extend_from_slice(&tmp2);

        if self.header == ZHEX {
            out.extend_from_slice(b"\r\n");

            if self.ftype != ZACK && self.ftype != ZFIN {
                out.push(XON);
            }
        }

        out 
    }

    pub fn get_frame_type(&self) -> u8 {
        self.ftype
    }

    pub fn get_header(&self) -> u8 {
        self.header
    }
}

fn get_crc(header: u8, buf: &[u8]) -> Vec<u8> {
    let offset = match header {
        ZHEX => 4,
        _    => 3,
    };

    match header {
        ZBIN32 => crc::get_crc32(&buf[offset..], None).to_vec(),
        _      => crc::get_crc16(&buf[offset..], None).to_vec(),
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hdr = match self.header {
            ZHEX   => "ZHEX",
            ZBIN   => "ZBIN",
            ZBIN32 => "ZBIN32",
            _      => "???",
        };

        let ft = match self.ftype {
            ZRQINIT    => "ZRQINIT",
            ZRINIT     => "ZRINIT",
            ZSINIT     => "ZSINIT",
            ZACK       => "ZACK",
            ZFILE      => "ZFILE",
            ZSKIP      => "ZSKIP",
            ZNAK       => "ZNAK",
            ZABORT     => "ZABORT",
            ZFIN       => "ZFIN",
            ZRPOS      => "ZRPOS",
            ZDATA      => "ZDATA",
            ZEOF       => "ZEOF",
            ZFERR      => "ZFERR",
            ZCRC       => "ZCRC",
            ZCHALLENGE => "ZCHALLENGE",
            ZCOMPL     => "ZCOMPL",
            ZCAN       => "ZCAN",
            ZFREECNT   => "ZFREECNT",
            ZCOMMAND   => "ZCOMMAND",
            ZSTDERR    => "ZSTDERR",
            _          => "???",
        };
        
        write!(f, "{}({})", hdr, ft)
    }
}

#[test]
fn test_frame() {
    assert_eq!(
        Frame::new(ZBIN, 0).build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(
        Frame::new(ZBIN32, 0).build(),
        vec![ZPAD, ZLDE, ZBIN32, 0, 0, 0, 0, 0, 29, 247, 34, 198]);

    assert_eq!(
        Frame::new(ZBIN, 0)
            .flags(&[1; 4])
            .build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 1, 1, 1, 1, 98, 148]);

    assert_eq!(
        Frame::new(ZBIN, 0)
            .flags(&[1; 4])
            .build(),
        vec![ZPAD, ZLDE, ZBIN, 0, 1, 1, 1, 1, 98, 148]);

    assert_eq!(
        Frame::new(ZHEX, 0)
            .flags(&[1; 4])
            .build(),
        vec![ZPAD, ZPAD, ZLDE, ZHEX,
            b'0', b'0',
            b'0', b'1',
            b'0', b'1',
            b'0', b'1',
            b'0', b'1',
            54, 50, 57, 52,
            b'\r', b'\n', XON]);
}
