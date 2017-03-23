use std::{thread, time};
use std::io::{Read, Write, Result};
use std::str::from_utf8;

use consts::*;
use proto::*;
use rwlog;

#[derive(Eq, PartialEq, Copy, Clone)]
enum RecvPhase {
    WaitZRQInit,
    WaitZData,
    WaitZEOF,
}

/// Receives data by Z-Modem protocol
pub fn recv<RW, W>(rw: RW, mut w: W) -> Result<usize> 
    where RW: Read + Write,
          W:  Write {

    let mut rw_log = rwlog::ReadWriteLog::new(rw);
    let mut phase = RecvPhase::WaitZRQInit;
    let mut count = 0;

    loop {
        if phase == RecvPhase::WaitZRQInit {
            write_zrinit(&mut rw_log)?;
        }

        if !find_zpad(&mut rw_log)? {
            continue;
        }

        let frame = match parse_header(&mut rw_log)? {
            Some(x) => x,
            None    => { recv_error(&mut rw_log, phase, count)?; continue },
        };

        match frame.get_frame_type() {
            ZRQINIT => {
                if phase == RecvPhase::WaitZEOF {
                    write_zack(&mut rw_log, count)?
                }
                else {
                    write_zrinit(&mut rw_log)?;
                    phase = RecvPhase::WaitZData;
                }
            },
            ZFILE  => {
                let mut buf = Vec::new();
                if recv_zlde_frame(frame.get_header(), &mut rw_log, &mut buf)?.is_none() {
                    write_znak(&mut rw_log)?;
                }
                else {
                    if let Ok(s) = from_utf8(&buf) {
                        debug!(target: "proto", "ZFILE supplied data: {}", s);
                    }

                    // TODO: don't ignore supplied data

                    write_zrpos(&mut rw_log, count)?;
                    phase = RecvPhase::WaitZData;
                }
            },
            ZDATA  => {
                phase = RecvPhase::WaitZEOF;

                if frame.get_count() != count {
                    write_zrpos(&mut rw_log, count)?;
                }
                else {
                    if !recv_data(frame.get_header(), &mut count, &mut rw_log, &mut w)? {
                        write_zrpos(&mut rw_log, count)?;
                    }
                }
            },
            ZEOF   => {
                if frame.get_count() != count {
                    error!("ZEOF offset mismatch: frame({}) != recv({})", frame.get_count(), count);

                    // receiver ignores the ZEOF because a new zdata is coming
                    continue;
                }

                write_zrinit(&mut rw_log)?;
            },
            ZFIN   => {
                write_zfin(&mut rw_log)?;
                thread::sleep(time::Duration::from_millis(10));
                break;
            },
            ZNAK   => write_zrpos(&mut rw_log, count)?,
            ZSINIT => write_zack(&mut rw_log, count)?,
            _      => recv_error(&mut rw_log, phase, count)?,
        };
    }

    Ok(count as usize)
}

fn recv_error<W>(w: &mut W, phase: RecvPhase, count: u32) -> Result<()>
    where W: Write {

    // TODO: flush input

    match phase {
        RecvPhase::WaitZRQInit => write_zrinit(w),
        RecvPhase::WaitZData   => write_znak(w),
        _                      => write_zrpos(w, count),
    }
}

