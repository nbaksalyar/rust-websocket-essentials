use std::{iter, fmt, cmp, error, u16};
use std::io::{self, Read, Write, Cursor};
use std::error::Error;

use byteorder::{self, ReadBytesExt, WriteBytesExt, BigEndian};

use StatusCode;

pub const PAYLOAD_LEN_U16: u8 = 126;
pub const PAYLOAD_LEN_U64: u8 = 127;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum OpCode {
    TextFrame = 1,
    BinaryFrame = 2,
    ConnectionClose = 8,
    Ping = 9,
    Pong = 0xA
}

impl OpCode {
    fn from(op: u8) -> Option<OpCode> {
        match op {
            1 => Some(OpCode::TextFrame),
            2 => Some(OpCode::BinaryFrame),
            8 => Some(OpCode::ConnectionClose),
            9 => Some(OpCode::Ping),
            0xA => Some(OpCode::Pong),
            _ => None
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    InvalidOpCode(u8),    
    Io(io::Error),
    UnexpectedEof
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> ParseError {
        ParseError::Io(err)
    }
}

impl From<byteorder::Error> for ParseError {
    fn from(err: byteorder::Error) -> ParseError {
        match err {
            byteorder::Error::UnexpectedEOF => ParseError::UnexpectedEof,
            byteorder::Error::Io(io_err) => ParseError::Io(io_err)
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::UnexpectedEof => write!(fmt, "Unexpected EOF"),
            ParseError::InvalidOpCode(ref opcode) => write!(fmt, "Invalid OpCode: {}", opcode),
            ParseError::Io(ref err) => write!(fmt, "I/O error: {}", err),
        }
    }
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        match *self {
            ParseError::InvalidOpCode(..) => "Invalid frame OpCode",
            ParseError::UnexpectedEof => "Reader unexpectedly returned 0 bytes",
            ParseError::Io(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            ParseError::Io(ref err) => Some(err),
            _ => None
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameHeader {  
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    masked: bool,
    opcode: OpCode,
    payload_length: u8
}

impl FrameHeader {
    fn new(len: usize, opcode: OpCode) -> FrameHeader {
        FrameHeader {
            fin: true,
            rsv1: false, rsv2: false, rsv3: false,
            masked: false,
            payload_length: Self::determine_len(len),
            opcode: opcode
        }
    }

    fn determine_len(len: usize) -> u8 {
        if len < (PAYLOAD_LEN_U16 as usize) {
            len as u8
        } else if len <= (u16::MAX as usize) {
            PAYLOAD_LEN_U16
        } else {
            PAYLOAD_LEN_U64
        }
    }

    fn parse(buf: u16) -> Result<FrameHeader, ParseError> {
        let opcode_num = ((buf >> 8) as u8) & 0x0F;
        let opcode = OpCode::from(opcode_num);

        if let Some(opcode) = opcode {
            Ok(FrameHeader {
                fin: (buf >> 8) & 0x80 == 0x80,
                rsv1: (buf >> 8) & 0x40 == 0x40,
                rsv2: (buf >> 8) & 0x20 == 0x20,
                rsv3: (buf >> 8) & 0x10 == 0x10,
                opcode: opcode,

                masked: buf & 0x80 == 0x80,
                payload_length: (buf as u8) & 0x7F,
            })
        } else {
            Err(ParseError::InvalidOpCode(opcode_num))
        }
    }

    fn serialize(&self) -> u16 {
        let b1 = ((self.fin as u8) << 7)
                  | ((self.rsv1 as u8) << 6)
                  | ((self.rsv2 as u8) << 5)
                  | ((self.rsv3 as u8) << 4)
                  | ((self.opcode as u8) & 0x0F);
        
        let b2 = ((self.masked as u8) << 7)
            | ((self.payload_length as u8) & 0x7F);

        ((b1 as u16) << 8) | (b2 as u16)
    }
}

enum FrameReaderState {
    ReadingHeader,
    ReadingLength,
    ReadingMask,
    ReadingPayload
}

pub struct BufferedFrameReader {
    state: FrameReaderState,
    frame_header: Option<FrameHeader>,
    frame_len: Option<usize>,
    frame_mask: Option<[u8; 4]>,
    buf: Cursor<Vec<u8>>
}

fn read_exact<R: Read>(input: &mut R, mut buf: &mut Vec<u8>, len: usize) -> io::Result<bool> {
    let to_read = cmp::min(len - buf.len(), len);
    let mut chunk = input.take(to_read as u64);
    let read_bytes = try!(chunk.read_to_end(&mut buf));
    return Ok(buf.len() >= len);
}

impl BufferedFrameReader {
    pub fn new() -> BufferedFrameReader {
        BufferedFrameReader {
            state: FrameReaderState::ReadingHeader,
            frame_header: None,
            frame_len: None,
            frame_mask: None,
            buf: Cursor::new(Vec::with_capacity(2048))
        }
    }

    fn read_header<R: Read>(&mut self, input: &mut R) -> Result<bool, ParseError> {
        if let Ok(false) = read_exact(input, self.buf.get_mut(), 2) {
            // Not enough bytes
            return Ok(false)
        }

        match FrameHeader::parse(self.buf.read_u16::<BigEndian>().unwrap()) {
            e @ Err(_) => e.map(|_| false),
            Ok(header) => {
                if header.payload_length < PAYLOAD_LEN_U16 {
                    self.frame_len = Some(header.payload_length as usize);
                    self.state = FrameReaderState::ReadingMask;
                    self.buf = Cursor::new(Vec::with_capacity(4));
                } else {
                    self.state = FrameReaderState::ReadingLength;
                    self.buf = Cursor::new(Vec::with_capacity(8));
                };
                self.frame_header = Some(header);

                Ok(true)
            }
        }
    }

    fn read_payload<R: Read>(&mut self, input: &mut R) -> Result<Option<Frame>, ParseError> {
        if let Ok(false) = read_exact(input, self.buf.get_mut(), self.frame_len.unwrap()) {
            // Not enough bytes
            return Ok(None);
        }

        // We have a complete frame now
        let mut payload = self.buf.get_ref().clone();

        if let Some(mask) = self.frame_mask {
            Frame::apply_mask(mask, &mut payload);
        }

        // Get back to reading the next frame's header
        self.state = FrameReaderState::ReadingHeader;
        self.buf = Cursor::new(Vec::with_capacity(2));

        Ok(Some(Frame {
            header: self.frame_header.clone().unwrap(),
            mask: self.frame_mask.clone(),
            payload: payload.into_boxed_slice()
        }))
    }

    pub fn read<R: Read>(&mut self, input: &mut R) -> Result<Option<Frame>, ParseError> {
        loop {
            match self.state {
                FrameReaderState::ReadingHeader => {
                    match self.read_header(input) {
                        Ok(true) => {},
                        Ok(false) => break,
                        err @ Err(_) => return err.map(|_| None)
                    }
                },
                FrameReaderState::ReadingLength => {
                    let (size, payload_len) = if let Some(ref header) = self.frame_header {
                        match header.payload_length {
                            PAYLOAD_LEN_U16 => (2, header.payload_length),
                            PAYLOAD_LEN_U64 => (8, header.payload_length),
                            _ => unreachable!()
                        }
                    } else {
                        unreachable!()
                    };

                    if let Ok(true) = read_exact(input, self.buf.get_mut(), size) {
                        self.frame_len = Some(Frame::read_length(payload_len, &mut self.buf).unwrap());
                        self.state = FrameReaderState::ReadingMask;
                        self.buf = Cursor::new(Vec::with_capacity(4));
                    } else {
                        break;
                    }
                },
                FrameReaderState::ReadingMask => {
                    let header = self.frame_header.as_ref().unwrap();
                    if !header.masked {
                        self.state = FrameReaderState::ReadingPayload;
                        self.buf = Cursor::new(Vec::with_capacity(self.frame_len.unwrap()));
                        continue;
                    }

                    if let Ok(true) = read_exact(input, self.buf.get_mut(), 4) {
                        self.frame_mask = Some({
                            let mask_buf = &self.buf.get_ref()[0..4];
                            [mask_buf[0], mask_buf[1], mask_buf[2], mask_buf[3]]
                        });
                        self.state = FrameReaderState::ReadingPayload;
                        self.buf = Cursor::new(Vec::with_capacity(self.frame_len.unwrap()));
                    } else {
                        break;
                    }
                },
                FrameReaderState::ReadingPayload => {
                    match self.read_payload(input) {
                        frame @ Ok(Some(..)) => return frame,
                        _ => break
                    }
                }
            }
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    header: FrameHeader,
    mask: Option<[u8; 4]>,
    pub payload: Box<[u8]>
}

impl<'a> From<&'a [u8]> for Frame {
    fn from(payload: &[u8]) -> Frame {
        Frame {
            header: FrameHeader::new(payload.len(), OpCode::BinaryFrame),
            payload: payload.to_owned().into_boxed_slice(),
            mask: None
        }
    }
}

impl<'a> From<&'a str> for Frame {
    fn from(payload: &str) -> Frame {
        Frame {
            header: FrameHeader::new(payload.len(), OpCode::TextFrame),
            payload: payload.to_owned().into_bytes().into_boxed_slice(),
            mask: None
        }
    }
}

impl Frame {
    pub fn close(status: StatusCode) -> Frame {
        let reason: &str = From::from(status.clone());
        let status_code: u16 = From::from(status);
        Self::close_custom(status_code, reason.as_bytes()).unwrap()
    }

    pub fn close_custom(status_code: u16, reason: &[u8]) -> Result<Frame, ParseError> {
        let body = Vec::with_capacity(2 + reason.len());

        let mut body_cursor = Cursor::new(body);
        try!(body_cursor.write_u16::<BigEndian>(status_code));
        try!(body_cursor.write(reason));

        Ok(Frame {
            header: FrameHeader::new(body_cursor.get_ref().len(), OpCode::ConnectionClose),
            payload: body_cursor.into_inner().into_boxed_slice(),
            mask: None
        })
    }

    pub fn close_from(recv_frame: &Frame) -> Frame {
        let body = if recv_frame.payload.len() > 0 {
            let status_code = &recv_frame.payload[0..2];
            let mut body = Vec::with_capacity(2);
            body.write(status_code).unwrap();
            body
        } else {
            Vec::new()
        };
        Frame {
            header: FrameHeader::new(body.len(), OpCode::ConnectionClose),
            payload: body.into_boxed_slice(),
            mask: None
        }
    }

    pub fn pong(ping_frame: &Frame) -> Frame {
        let payload = ping_frame.payload.clone();
        Frame {
            header: FrameHeader::new(payload.len(), OpCode::Pong),
            payload: payload,
            mask: None
        }
    }

    pub fn ping(payload: Box<[u8]>) -> Frame {
        Frame {
            header: FrameHeader::new(4, OpCode::Ping),
            payload: payload,
            mask: None
        }
    }

    pub fn write<W: Write>(&self, output: &mut W) -> io::Result<()> {
        let hdr = self.header.serialize();
        try!(output.write_u16::<BigEndian>(hdr));

        match self.header.payload_length {
            PAYLOAD_LEN_U16 => try!(output.write_u16::<BigEndian>(self.payload.len() as u16)),
            PAYLOAD_LEN_U64 => try!(output.write_u64::<BigEndian>(self.payload.len() as u64)),
            _ => {}
        }

        try!(output.write(&self.payload));
        Ok(())
    }

    pub fn read<R: Read>(input: &mut R) -> Result<Frame, ParseError> {
        let buf = try!(input.read_u16::<BigEndian>());
        let header = try!(FrameHeader::parse(buf));

        let len = try!(Self::read_length(header.payload_length, input));
        let mask_key = if header.masked {
            let mask = try!(Self::read_mask(input));
            Some(mask)
        } else {
            None
        };
        let mut payload = try!(Self::read_payload(len, input));

        if let Some(mask) = mask_key {
            Self::apply_mask(mask, &mut payload);
        }

        Ok(Frame {
            header: header,
            payload: payload,
            mask: mask_key
        })
    }

    pub fn get_opcode(&self) -> OpCode {
        self.header.opcode.clone()
    }

    pub fn is_close(&self) -> bool {
        self.header.opcode == OpCode::ConnectionClose
    }

    fn apply_mask(mask: [u8; 4], bytes: &mut [u8]) {
        for (idx, c) in bytes.iter_mut().enumerate() {
            *c = *c ^ mask[idx % 4];
        }
    }

    fn read_mask<R: Read>(input: &mut R) -> io::Result<[u8; 4]> {
        let mut buf = [0; 4];
        try!(input.read(&mut buf));
        Ok(buf)
    }

    fn read_payload<R: Read>(payload_len: usize, input: &mut R) -> io::Result<Box<[u8]>> {
        let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
        payload.extend(iter::repeat(0).take(payload_len));
        try!(input.read(&mut payload));
        Ok(payload.into_boxed_slice())
    }

    fn read_length<R: Read>(payload_len: u8, input: &mut R) -> io::Result<usize> {
        return match payload_len {
            PAYLOAD_LEN_U64 => input.read_u64::<BigEndian>().map(|v| v as usize).map_err(From::from),
            PAYLOAD_LEN_U16 => input.read_u16::<BigEndian>().map(|v| v as usize).map_err(From::from),
            _ => Ok(payload_len as usize) // payload_len < 127
        }
    }
}

mod test {
    use std::io::Cursor;

    use super::*;
    use StatusCode;

    #[test]
    fn opcode_numbers() {
        assert!(OpCode::from(1).is_some());
        assert!(OpCode::from(2).is_some());
        assert_eq!(OpCode::from(128), None);
    }

    #[test]
    fn determine_header_len() {
        assert_eq!(FrameHeader::determine_len(42), 42);
        assert_eq!(FrameHeader::determine_len(2000), PAYLOAD_LEN_U16);
        assert_eq!(FrameHeader::determine_len(65535), PAYLOAD_LEN_U16);
        assert_eq!(FrameHeader::determine_len(65537), PAYLOAD_LEN_U64);
    }

    #[test]
    fn create_close_frame_from_status() {
        let f = Frame::close(StatusCode::InternalServerError);
        assert_eq!(f.header.opcode, OpCode::ConnectionClose);
        assert_eq!(&*f.payload, b"\x03\xF3Internal Server Error");

        let f = Frame::close(StatusCode::NormalClosure);
        assert_eq!(f.header.opcode, OpCode::ConnectionClose);
        assert_eq!(&*f.payload, b"\x03\xE8Normal Closure");
    }

    #[test]
    fn buffered_read_invalid_frame() {
        let mut frame_reader = BufferedFrameReader::new();

        let mut frame = Cursor::new(b"\x00\x00");

        let result = frame_reader.read(&mut frame);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_header() {
        let header = FrameHeader::new(16, OpCode::TextFrame);
        assert_eq!(header.payload_length, 16);
        assert_eq!(header.serialize(), 0b10000001_00010000);

        let header = FrameHeader::new(8, OpCode::BinaryFrame);
        assert_eq!(header.payload_length, 8);
        assert_eq!(header.serialize(), 0b10000010_00001000);
    }

    #[test]
    fn frame_serialize() {
        let mut fb = Vec::<u8>::new();

        let f = Frame::from("hello");
        f.write(&mut fb);

        assert_eq!(&*fb, b"\x81\x05hello");
    }

    #[test]
    fn frame_read() {
        let fr = Frame::read(&mut Cursor::new(b"\x81\x05hello")).unwrap();

        assert_eq!(fr.get_opcode(), OpCode::TextFrame);
        assert_eq!(fr.header.payload_length, 5);
        assert_eq!(&*fr.payload, b"hello");
    }

    #[test]
    fn buffered_read_frame() {
        let mut frame_reader = BufferedFrameReader::new();

        let read_result = frame_reader.read(&mut Cursor::new(b"\x81\x05hello"));
        assert!(read_result.is_ok());

        let fr = read_result.unwrap().unwrap();
        assert_eq!(fr.get_opcode(), OpCode::TextFrame);
        assert_eq!(fr.header.payload_length, 5);
        assert_eq!(&*fr.payload, b"hello");
    }

    #[test]
    fn buffered_read_masked_frame() {
        let read_result = BufferedFrameReader::new().read(&mut Cursor::new(b"\x81\x82\x01\x02\x03\x04\x69\x6b"));
        assert!(read_result.is_ok());

        let fr = read_result.unwrap().unwrap();

        assert_eq!(fr.header.masked, true);
        assert_eq!(fr.header.payload_length, 2);
        assert_eq!(&*fr.payload, b"hi");
    }

    #[test]
    fn buffered_read_partial() {
        let mut frame_reader = BufferedFrameReader::new();

        let frame = frame_reader.read(&mut Cursor::new(b"\x81")).unwrap();
        assert!(frame.is_none());
        assert!(frame_reader.frame_header.is_none());

        let frame = frame_reader.read(&mut Cursor::new(b"\x10")).unwrap();
        assert!(frame.is_none());
        assert!(frame_reader.frame_header.is_some());

        let header = frame_reader.frame_header.unwrap();
        assert_eq!(header.fin, true);
        assert_eq!(header.payload_length, 0x10);
    }
}
