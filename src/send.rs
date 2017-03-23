use std::io::{Read, Write, Result, Seek, SeekFrom};

use consts::*;
use proto::*;
use rwlog;

const SUBPACKET_SIZE: usize = 1024 * 8;
const SUBPACKET_PER_ACK: usize = 10;

#[derive(Eq, PartialEq, Copy, Clone)]
enum SendPhase {
    WaitZRInit,
    SendStart,
    FileSent,
}

/// Sends data (file) by Z-Modem protocol
pub fn send<RW, R>(rw: RW, r: &mut R, filename: &str, filesize: Option<u32>) -> Result<()> 
    where RW: Read + Write,
          R:  Read + Seek {

    let mut rw_log = rwlog::ReadWriteLog::new(rw);
    let mut phase = SendPhase::WaitZRInit;

    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32;

    //write_zrqinit(&mut rw_log)?;

    loop {
        rw_log.flush()?;
        if !find_zpad(&mut rw_log)? {
            continue;
        }

        let frame = match parse_header(&mut rw_log)? {
            Some(x) => x,
            None    => { send_error(&mut rw_log, phase)?; continue },
        };

        match frame.get_frame_type() {
            ZRINIT => {
                match phase {
                    SendPhase::WaitZRInit => {
                        write_zfile(&mut rw_log, filename, filesize)?;
                        phase = SendPhase::SendStart;
                    },
                    SendPhase::FileSent => {
                        // ZHEX|ZFIN
                        write_zfin(&mut rw_log)?;
                    },

                    _ => (),
                }
            },
            // ZCRCG - best perf
            // ZCRCQ - mid perf
            // ZCRCW - worst perf
            // ZCRCE - send at end
            ZRPOS | ZACK => {
                offset = frame.get_count();
                r.seek(SeekFrom::Start(offset as u64))?;

                let num = r.read(&mut data)?;

                if num == 0 {
                    write_zeof(&mut rw_log, offset)?;
                    phase = SendPhase::FileSent;
                }
                else {
                    // ZBIN32|ZDATA
                    write_zdata(&mut rw_log, offset)?;

                    let mut i = 0;
                    loop {
                        i += 1;

                        write_zlde_data(&mut rw_log, ZCRCG, &data[..num])?;
                        offset += num as u32;

                        let num = r.read(&mut data)?;
                        if num < data.len() || i >= SUBPACKET_PER_ACK {
                            write_zlde_data(&mut rw_log, ZCRCW, &data[..num])?;
                            break;
                        }
                    }
                }
            },
            ZFIN => {
                // write OO (Over & Out)
                rw_log.write_all("OO".as_bytes())?;

                // finish loop
                break;
            },
            x    => {
                error!("unexpected frame: {}", x);
                send_error(&mut rw_log, phase)?;
            },
        }
    }

    Ok(())
}

fn send_error<W>(w: &mut W, phase: SendPhase) -> Result<()>
    where W: Write {

    // TODO: flush input

    match phase {
        SendPhase::WaitZRInit => write_zrqinit(w),
        _ => write_znak(w),
    }
}
