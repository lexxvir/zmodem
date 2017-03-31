use std::io::{Read, Write, Result, Seek, SeekFrom};
use std::fs::File;
use std::os::unix::io::AsRawFd;

use mio::*;
use mio::unix::{EventedFd};

use consts::*;
use proto::*;
use rwlog;
use frame::*;

const SUBPACKET_SIZE: usize = 1024 * 8;
const SUBPACKET_PER_ACK: usize = 10;

#[derive(Debug, PartialEq)]
enum State {
    /// Waiting ZRINIT invite (do nothing)
    WaitingInit,

    /// Sending ZRQINIT
    SendingZRQINIT,

    /// Sending ZFILE frame
    SendingZFILE,

    /// Do nothing, just waiting for ZPOS
    WaitingZPOS,

    /// Sending ZDATA & subpackets
    SendingData,

    SendingZCRCG(usize),

    /// Sending ZFIN
    SendingZFIN,

    /// All works done, exiting
    Done,
}

impl State {
    fn new() -> State {
        State::WaitingInit
    }

    fn next(self, frame: &Frame) -> State {
        match (self, frame.get_frame_type()) {
            (State::WaitingInit,  ZRINIT)   => State::SendingZFILE,
            (State::WaitingInit,  _)        => State::SendingZRQINIT,

            (State::SendingZRQINIT, ZRINIT) => State::SendingZFILE,

            (State::SendingZFILE, ZRPOS)    => State::SendingData,
            (State::SendingZFILE, ZRINIT)   => State::WaitingZPOS,

            (State::WaitingZPOS, ZRPOS)     => State::SendingData,

            (State::SendingData,  ZACK)     => State::SendingData,
            (State::SendingData,  ZRPOS)    => State::SendingData,
            (State::SendingData,  ZRINIT)   => State::SendingZFIN,

            (State::SendingZFIN,  ZFIN)     => State::Done,

            (s, _) => {
               error!("Unexpected (state, frame) combination: {:#?} {}", s, frame);
               s // don't change current state
            },
        }
    }
}

pub fn send<RW, R>(rw: RW, r: &mut R, filename: &str, filesize: Option<u32>) -> Result<()> 
    where RW: Read + Write,
          R:  Read + Seek
{
    let mut rw_log = rwlog::ReadWriteLog::new(rw);

    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32;

    write_zrqinit(&mut rw_log)?;

    let mut state = State::new();

    while state != State::Done {
        rw_log.flush()?;

        if !find_zpad(&mut rw_log)? {
            continue;
        }

        let frame = match parse_header(&mut rw_log)? {
            Some(x) => x,
            None    => { write_znak(&mut rw_log)?; continue },
        };

        state = state.next(&frame);
        debug!("State: {:?}", state);

        // do things according new state
        match state {
            State::SendingZRQINIT => {
                write_zrqinit(&mut rw_log)?;
            },
            State::SendingZFILE => {
                write_zfile(&mut rw_log, filename, filesize)?;
            },
            State::SendingData  => {
                offset = frame.get_count();
                r.seek(SeekFrom::Start(offset as u64))?;

                let num = r.read(&mut data)?;

                if num == 0 {
                    write_zeof(&mut rw_log, offset)?;
                }
                else {
                    // ZBIN32|ZDATA
                    // ZCRCG - best perf
                    // ZCRCQ - mid perf
                    // ZCRCW - worst perf
                    // ZCRCE - send at end
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
            State::SendingZFIN  => {
                write_zfin(&mut rw_log)?;
            },
            State::Done         => {
                write_over_and_out(&mut rw_log)?;
            },
            _ => (),
        }
    }

    Ok(())
}

const READ: Token = Token(0);
const WRITE: Token = Token(1);

pub fn send2<R>(mut read: &mut File, mut write: &mut File, r: &mut R, filename: &str, filesize: Option<u32>) //-> Result<()> 
    where R: Read + Seek
{
    let rfd = read.as_raw_fd();
    let rfd = EventedFd( &rfd );

    let wfd = write.as_raw_fd();
    let wfd = EventedFd( &wfd );

    let poll = Poll::new().unwrap();
    poll.register(&rfd, READ, Ready::readable(), PollOpt::level()).unwrap();

    let mut state = State::new();
    let mut wrbuf = Vec::new();

    let mut data = [0; SUBPACKET_SIZE];
    let mut offset: u32 = 0;
    let mut num = 0;

    let mut events = Events::with_capacity(1024);

    while state != State::Done {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            if event.readiness().is_readable() {
                debug!("read");

                if let Some(frame) = get_frame(read).unwrap() {
                    state = state.next(&frame);
                    debug!("State: {:?}", state);

                    // do things according new state
                    match state {
                        State::SendingZRQINIT => {
                            write_zrqinit(&mut wrbuf).unwrap();
                        },
                        State::SendingZFILE => {
                            write_zfile(&mut wrbuf, filename, filesize).unwrap();
                        },
                        State::SendingZFIN  => {
                            write_zfin(&mut wrbuf).unwrap();
                        },
                        State::Done         => {
                            write_over_and_out(&mut wrbuf).unwrap();
                        },
                        State::SendingData  => {
                            offset = frame.get_count();
                            r.seek(SeekFrom::Start(offset as u64)).unwrap();

                            num = r.read(&mut data).unwrap();

                            if num == 0 {
                                write_zeof(&mut wrbuf, offset).unwrap();
                            }
                            else {
                                // ZBIN32|ZDATA
                                // ZCRCG - best perf
                                // ZCRCQ - mid perf
                                // ZCRCW - worst perf
                                // ZCRCE - send at end
                                write_zdata(&mut wrbuf, offset).unwrap();
                                state = State::SendingZCRCG(0);
                            }
                        },
                        _ => (),
                    }
                }
                else {
                    //write_znak(&mut wrbuf).unwrap();
                }

                let _ = poll.register(&wfd, WRITE, Ready::writable(), PollOpt::edge());
            }

            if event.readiness().is_writable() {
                debug!("write");
                if !wrbuf.is_empty() {
                    write.write_all(&wrbuf).unwrap();
                    wrbuf.clear();
                }

                if let State::SendingZCRCG(i) = state {
                    if num < data.len() /*|| i >= SUBPACKET_PER_ACK*/ {
                        write_zlde_data(&mut wrbuf, ZCRCW, &data[..num]).unwrap();
                        offset += num as u32;

                        write.write_all(&wrbuf).unwrap();
                        wrbuf.clear();

                        state = State::SendingData;
                        poll.deregister(&wfd).unwrap();
                    }
                    else {
                        write_zlde_data(&mut wrbuf, ZCRCG, &data[..num]).unwrap();
                        offset += num as u32;

                        write.write_all(&wrbuf).unwrap();
                        wrbuf.clear();

                        state = State::SendingZCRCG(i + 1);
                        num = r.read(&mut data).unwrap();
                    }
                }
                else {
                    poll.deregister(&wfd).unwrap();
                }
            }
        }
    }

    //Result::Ok(())
}

fn get_frame<R: Read>(read: &mut R) -> Result<Option<Frame>> {
    if !find_zpad(read)? {
        return Ok(None);
    }

    parse_header(read)
}

