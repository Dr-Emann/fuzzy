use crapsum::*;
use transport::{self, exchange_packet};

use std::io::{self, Read, Write, Seek, SeekFrom, ErrorKind};
use std::{cmp, fmt};
use std::error::Error as StdError;
use std::mem::transmute;

#[derive(Debug)]
pub enum Error {
    Transport(transport::Error),
    DataEmpty,
    DataTooLarge,
    ZeroLength,
    ProtocolViolation,
    WrongCrapsum,
    InvalidResponse(Vec<u8>),
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Transport(transport::Error::Io(io_err)) => io_err,
            input_err @ Error::Transport(_)
                | input_err @ Error::DataEmpty
                | input_err @ Error::DataTooLarge
                | input_err @ Error::ZeroLength => io::Error::new(ErrorKind::InvalidInput, input_err),
            data_err @ Error::ProtocolViolation
                | data_err @ Error::WrongCrapsum
                | data_err @ Error::InvalidResponse(_) => io::Error::new(ErrorKind::InvalidData, data_err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Transport(ref e) => fmt::Display::fmt(e, f),
            ref other => f.write_str(other.description()),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Transport(ref e) => e.description(),
            Error::DataEmpty => "Data Empty",
            Error::DataTooLarge => "Data too large",
            Error::ZeroLength => "Zero Length",
            Error::ProtocolViolation => "Protocol Violation",
            Error::WrongCrapsum => "Wrong Crapsum",
            Error::InvalidResponse(_) => "Invalid Response",
        }
    }
}

enum Command {
    CheckStatus,
    WriteMemRegion { addr: u32, data: Vec<u8> },
    ReadMemRegion { addr: u32, length: u32 },
    ReadMemRegionData,
    Execute { entry: u32 },
}

#[derive(Eq, PartialEq)]
enum Response {
    UnexpectedCommand,
    OkWithCrapsum(Crapsum),
    ReadMemRegionData(Vec<u8>),
}

impl Response {
    fn parse(data: Vec<u8>) -> Result<Response, Error> {
        if data.is_empty() {
            return Err(Error::InvalidResponse(data));
        }

        match data[0] {
            0x00 => {
                if data.len() != 1 {
                    return Err(Error::InvalidResponse(data));
                }

                Ok(Response::UnexpectedCommand)
            }
            0x01 => {
                if data.len() != 5 {
                    return Err(Error::InvalidResponse(data));
                }

                let mut state = 0;
                for i in 1..5 {
                    state >>= 8;
                    state |= (data[i] as u32) << 24;
                }

                Ok(Response::OkWithCrapsum(Crapsum::from_state(state)))
            }
            0x02 => {
                if data.len() < 2 {
                    return Err(Error::InvalidResponse(data));
                }

                Ok(Response::ReadMemRegionData(data[1..].iter().cloned().collect()))
            }
            _ => Err(Error::InvalidResponse(data))
        }
    }
}

pub struct RemoteMem<'a, P: 'a> {
    port: &'a mut P,
    position: u32,
}

impl<'a, P: 'a> RemoteMem<'a, P> {
    pub fn new(port: &'a mut P) -> RemoteMem<'a, P> {
        RemoteMem{ port: port, position: 0 }
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn set_position(&mut self, pos: u32) {
        self.position = pos
    }
}

impl<'a, P: 'a> Seek for RemoteMem<'a, P> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => {
                self.set_position(pos as u32);
                pos
            },
            SeekFrom::End(_) => {
                return Err(io::Error::new(ErrorKind::InvalidInput, "Unable to seek from end"));
            },
            SeekFrom::Current(offset) => {
                let new_pos = (self.position() as i64 + offset) as u32;
                self.set_position(new_pos);
                u64::from(new_pos)
            },
        };
        Ok(new_pos)
    }
}

impl<'a, P: 'a + Read + Write> Read for RemoteMem<'a, P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }
        let len = cmp::min(buf.len(), 256 - 5);
        let buf = &mut buf[..len];

        let data = read_mem_single(self.port, self.position, len as u32)?;
        buf.copy_from_slice(&data);

        Ok(len)
    }
}

impl<'a, P: 'a + Read + Write> Write for RemoteMem<'a, P> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }
        let len = cmp::min(buf.len(), 256 - 1);
        let buf = &buf[..len];

        write_mem_single(self.port, self.position, buf)?;

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_mem_single<P: Read + Write>(port: &mut P, addr: u32, len: u32) -> Result<Vec<u8>, Error> {
    assert!(len > 0 && len <= 256 - 1);

    let (response, expected_crapsum) =
        issue_command(port, Command::ReadMemRegion { addr: addr, length: len })?;

    match response {
        Response::OkWithCrapsum(crapsum) => {
            if crapsum != expected_crapsum {
                return Err(Error::WrongCrapsum);
            }
        }
        _ => {
            return Err(Error::ProtocolViolation);
        }
    }

    for _ in 0..5 {
        match issue_command(port, Command::ReadMemRegionData) {
            Ok((Response::ReadMemRegionData(data), _)) => {
                if data.len() as u32 != len {
                    return Err(Error::ProtocolViolation);
                }
                return Ok(data)
            }
            Ok(_) => {
                return Err(Error::ProtocolViolation);
            }
            Err(_) => {}
        }
    }
    Err(Error::ProtocolViolation)
}

fn write_mem_single<P: Read + Write>(port: &mut P, addr: u32, data: &[u8]) -> Result<(), Error> {
    assert!(data.len() > 0 && data.len() <= 256 - 5);


    let (response, expected_crapsum) =
        issue_command(port, Command::WriteMemRegion { addr: addr, data: data.to_vec() })?;

    match response {
        Response::OkWithCrapsum(crapsum) => {
            if crapsum != expected_crapsum {
                return Err(Error::WrongCrapsum);
            }
        }
        _ => {
            return Err(Error::ProtocolViolation);
        }
    }

    for _ in 0..5 {
        match issue_command(port, Command::CheckStatus) {
            Ok((Response::OkWithCrapsum(crapsum), _)) => {
                if crapsum != expected_crapsum {
                    return Err(Error::WrongCrapsum);
                }
                return Ok(());
            }
            Ok(_) => {
                return Err(Error::ProtocolViolation);
            }
            Err(_) => {}
        }
    }
    Err(Error::ProtocolViolation)
}

pub fn execute<P: Read + Write>(port: &mut P, entry: u32) -> Result<(), Error> {
    let (response, expected_crapsum) = issue_command(port, Command::Execute { entry: entry })?;

    match response {
        Response::OkWithCrapsum(crapsum) => {
            if crapsum != expected_crapsum {
                return Err(Error::WrongCrapsum);
            }
        }
        _ => {
            return Err(Error::ProtocolViolation);
        }
    }

    let mut status_tries = 0;
    loop {
        if let Ok((response, expected_crapsum)) = issue_command(port, Command::CheckStatus) {
            match response {
                Response::OkWithCrapsum(crapsum) => {
                    if crapsum != expected_crapsum {
                        return Err(Error::WrongCrapsum);
                    }

                    break;
                }
                _ => {
                    return Err(Error::ProtocolViolation);
                }
            }
        }

        status_tries += 1;
        if status_tries >= 5 {
            return Err(Error::ProtocolViolation);
        }
    }

    Ok(())
}

fn issue_command<P: Read + Write>(port: &mut P, command: Command) -> Result<(Response, Crapsum), Error> {
    let packet = match command {
        Command::CheckStatus => vec![0x00],
        Command::WriteMemRegion { addr, data } => {
            if data.is_empty() {
                return Err(Error::DataEmpty);
            }

            if data.len() > 256 - 5 {
                return Err(Error::DataTooLarge);
            }

            let addr_bytes: [u8; 4] = unsafe { transmute(addr.to_le()) };

            [0x01].iter()
                .chain(addr_bytes.iter())
                .chain(data.iter())
                .cloned()
                .collect::<Vec<_>>()
        }
        Command::ReadMemRegion { addr, length } => {
            if length == 0 {
                return Err(Error::ZeroLength);
            }

            let addr_bytes: [u8; 4] = unsafe { transmute(addr.to_le()) };

            [0x02].iter()
                .chain(addr_bytes.iter())
                .chain([(length - 1) as u8].iter())
                .cloned()
                .collect::<Vec<_>>()
        }
        Command::ReadMemRegionData => vec![0x03],
        Command::Execute { entry } => {
            let entry_bytes: [u8; 4] = unsafe { transmute(entry.to_le()) };

            [0x04].iter()
                .chain(entry_bytes.iter())
                .cloned()
                .collect::<Vec<_>>()
        }
    };
    let packet_crapsum = Crapsum::compute(&packet);
    let received_packet = exchange_packet(port, &packet).map_err(|e| Error::Transport(e))?;
    Response::parse(received_packet).map(|response| (response, packet_crapsum))
}
