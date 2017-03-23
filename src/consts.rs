pub const ZPAD:   u8 = b'*';
pub const ZLDE:   u8 = 0x18;
pub const ZLDEE:  u8 = 0x58;
pub const ZBIN:   u8 = b'A'; // 0x41
pub const ZHEX:   u8 = b'B'; // 0x42
pub const ZBIN32: u8 = b'C'; // 0x43

pub const ESC_FF: u8 = b'm';
pub const ESC_7F: u8 = b'l';

/// Frame types
pub const ZRQINIT: u8 =	0;	/* Request receive init */
pub const ZRINIT:  u8 = 1;	/* Receive init */
pub const ZSINIT:  u8 = 2;	/* Send init sequence (optional) */
pub const ZACK:    u8 = 3;		/* ACK to above */
pub const ZFILE:   u8 = 4;		/* File name from sender */
pub const ZSKIP:   u8 = 5;		/* To sender: skip this file */
pub const ZNAK:    u8 = 6;		/* Last packet was garbled */
pub const ZABORT:  u8 = 7;	/* Abort batch transfers */
pub const ZFIN:    u8 = 8;		/* Finish session */
pub const ZRPOS:   u8 = 9;		/* Resume data trans at this position */
pub const ZDATA:   u8 = 10;	/* Data packet(s) follow */
pub const ZEOF:    u8 = 11;		/* End of file */
pub const ZFERR:   u8 = 12;	/* Fatal Read or Write error Detected */
pub const ZCRC:    u8 = 13;		/* Request for file CRC and response */
pub const ZCHALLENGE: u8 = 14;	/* Receiver's Challenge */
pub const ZCOMPL:   u8 = 15;	/* Request is complete */
pub const ZCAN:     u8 = 16;		/* Other end canned session with CAN*5 */
pub const ZFREECNT: u8 = 17;	/* Request for free bytes on filesystem */
pub const ZCOMMAND: u8 = 18;	/* Command from sending program */
pub const ZSTDERR:  u8 = 19;	/* Output to standard error, data follows */

/* ZDLE sequences */
pub const ZCRCE: u8 = b'h';	/* CRC next, frame ends, header packet follows */
pub const ZCRCG: u8 = b'i';	/* CRC next, frame continues nonstop */
pub const ZCRCQ: u8 = b'j';	/* CRC next, frame continues, ZACK expected */
pub const ZCRCW: u8 = b'k';	/* CRC next, ZACK expected, end of frame */

pub const XON: u8 = 0x11;
