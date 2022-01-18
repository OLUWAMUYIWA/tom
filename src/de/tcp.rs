use std::{fmt::Debug, u16};

use nom::{bytes::complete::tag, Finish, IResult};

//20 to 60 bytes
pub type Connection = (u16, u16);
pub struct TcpSegment {
    hdr: TcpHeader,
    data: Vec<u8>,
}

pub struct TcpHeader {
    pub port_pair: Connection,
    seq_no: u32,
    ack_no: u32,
    //Header length = Header length field value x 4 bytes. scaling factor of 4
    hdr_len: u8,
    //6 bits unused
    rsvd_bits: u8,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
    window_size: u16,
    checksum: u16,
    urgent_ptr: u16,
    options: [u8; 40],
}

pub enum TcpOptions<'o> {
    //End Of Option List
    EOP,
    NoOp,
    //Maximum Segment Size
    MSS(u16),
    //Window Size Shift
    WSS(u8),
    //Selective Acknowledgment Permitted
    SAP(bool),
    //Selective Acknowledgment. Blocks Of Data Selectively Acknowledged
    SA(&'o [u8]),
    // //Alternate Checksum Algorithm
    // ACA(bool),
    // //Alternate Checksum
    // AC(&'o [u8])
    Other { kind: u8, data: &'o [u8] },
}

impl TcpHeader {
    pub fn source_port(&self) -> u16 {
        self.port_pair.0
    }

    pub fn dest_port(&self) -> u16 {
        self.port_pair.0
    }

    pub fn port_pair(&self) -> (u16, u16) {
        self.port_pair
    }

    pub fn seq_no(&self) -> u32 {
        self.seq_no
    }

    pub fn hdr_len(&self) -> u8 {
        //header length is not supposed to exceed 40 bytes. between 20 and 40
        self.hdr_len.saturating_mul(4)
    }

    pub fn window_size(&self) -> u16 {
        self.window_size
    }
}

//TODO: incomplete
impl Debug for TcpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "TcpHeader: {{\n Connection pair: (Source port, Destination port): ({} {}),\n  ack number: {}\n
            header length: {}\nreserved bits: {}\nurg: {}\nack: {}\npsh: {}\nrst: {}\nsyn: {}\nfin: {}\nwindow size: {}\nchecksum: {}\nurgent pointer: {}\noptions:{:?} \n}}",
            self.port_pair.0, self.port_pair.1, self.ack,
            self.hdr_len,
		    self.rsvd_bits,
		    self.urg,
		    self.ack,
		    self.psh,
		    self.rst,
		    self.syn,
		    self.fin,
		    self.window_size,
		    self.checksum,
		    self.urgent_ptr,
		    self.options,
        )
    }
}

impl Default for TcpHeader {
    fn default() -> Self {
        todo!()
    }
}

impl<'t> From<&'t [u8]> for TcpHeader {
    fn from(_: &'t [u8]) -> Self {
        todo!()
    }
}

#[derive(Debug)]
enum ErrorKind {
    ParseU8,
    ParseU16,
    Unknown,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::ParseU8 => {
                writeln!(f, "Could not parse unsigned 8-bit integer")
            }
            ErrorKind::ParseU16 => {
                writeln!(f, "Could not parse unsigned 16-bit integer")
            }
            &ErrorKind::Unknown => {
                writeln!(f, "Not known")
            }
        }
    }
}

impl From<ErrorKind> for nom::Err<ErrorKind> {
    fn from(err: ErrorKind) -> Self {
        nom::Err::Error(err)
    }
}

impl From<nom::Err<ErrorKind>> for ErrorKind {
    fn from(err: nom::Err<ErrorKind>) -> ErrorKind {
        if let nom::Err::Error(e) = err {
            e
        } else {
            ErrorKind::Unknown
        }
    }
}

impl<'t> nom::error::ParseError<&'t [u8]> for ErrorKind {
    fn from_error_kind(input: &'t [u8], kind: nom::error::ErrorKind) -> Self {
        unimplemented!()
    }

    fn append(input: &'t [u8], kind: nom::error::ErrorKind, other: Self) -> Self {
        unimplemented!()
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        unimplemented!()
    }

    fn description(&self) -> &str {
        unimplemented!()
    }
}

type NomErrType<'t> = (&'t [u8], ErrorKind);

mod parsers {
    use super::*;
    use std::convert::TryFrom;

    use nom::{
        bits::streaming::take as bit_take,
        bytes::streaming::take,
        combinator::map,
        multi::many_m_n,
        number::complete::{be_i16, be_u16, be_u32, le_u16},
        sequence::tuple,
        IResult,
    };

    //TCP options
    const OPT_EOP: u8 = 0x00;
    const OPT_NOOP: u8 = 0x01;
    const OPT_MSS: u8 = 0x02;
    const OPT_WS: u8 = 0x03;
    const OPT_SACKPERM: u8 = 0x04;
    const OPT_SACKRNG: u8 = 0x05;

    fn take_n<'t>(n: u8, stream: &'t [u8]) -> IResult<&'t [u8], &'t [u8]> {
        take(n)(stream)
    }

    fn take_2<'t>(stream: &'t [u8]) -> IResult<&'t [u8], &'t [u8]> {
        take_n(2, stream)
    }

    fn take_4<'t>(stream: &'t [u8]) -> IResult<&'t [u8], &'t [u8]> {
        take_n(4, stream)
    }

    fn u16_val<'t>(stream: &'t [u8]) -> IResult<&'t [u8], u16> {
        map(take_2, |out: &'t [u8]| {
            let mut arr = [0u8; 2];
            arr[0] = out[0];
            arr[1] = out[1];
            u16::from_be_bytes(arr)
        })(stream)
    }

    fn u32_val<'t>(stream: &'t [u8]) -> IResult<&'t [u8], u32> {
        map(take_4, |out: &'t [u8]| {
            //we can unwrap because take_4 will always give us 4 bytes
            let arr: [u8; 4] = TryFrom::try_from(out).unwrap();
            u32::from_be_bytes(arr)
        })(stream)
    }

    fn bits_offset_n_m<'t>(input: (&'t [u8], usize), count: usize) -> IResult<(&[u8], usize), u8> {
        bit_take(count)(input)
    }

    fn take_4bits<'t>(input: (&'t [u8], usize)) -> IResult<(&[u8], usize), u8> {
        bits_offset_n_m(input, 4)
    }

    fn take_6bits<'t>(input: (&'t [u8], usize)) -> IResult<(&[u8], usize), u8> {
        bits_offset_n_m(input, 6)
    }

    fn take_1bit<'t>(input: (&'t [u8], usize)) -> IResult<(&[u8], usize), u8> {
        bits_offset_n_m(input, 1)
    }

    fn take_first_4th_row<'t>(
        input: (&'t [u8], usize),
    ) -> IResult<(&[u8], usize), (u8, u8, Vec<u8>)> {
        tuple((take_4bits, take_6bits, many_m_n(6, 6, take_1bit)))(input)
    }

    fn parse_options<'o>(
        b: &'o [u8],
    ) -> Result<(&'o [u8], TcpOptions<'o>), Box<dyn std::error::Error>> {
        //assuming that option starts from the beginning of b
        let len;
        let option;
        match *b.get(0).ok_or(ErrorKind::ParseU8)? {
            OPT_EOP => {
                len = 1;
                option = TcpOptions::EOP;
            }
            OPT_NOOP => {
                len = 1;
                option = TcpOptions::NoOp;
            }
            other => {
                unimplemented!()
            }
        };
        Ok((&b[len..], option))
    }

    fn header<'t>(input: &'t [u8]) -> IResult<&[u8], TcpHeader> {
        let (rem, (port_pair, seq_ack)) =
            tuple((many_m_n(2, 2, be_u16), many_m_n(2, 2, be_u32)))(input)?;
        let (rem, (hdr_len, rsvd, ctrls)) = take_first_4th_row((rem, 0)).unwrap();
        let (rem, wnd) = take::<_, _, ErrorKind>(16u8)(rem.0).unwrap();
        let (chk, up) = tuple::<_, _, ErrorKind, _>((le_u16, le_u16))(rem).unwrap();
        todo!()
    }
}

fn try_this() {
    let v = vec![1u8, 2, 3, 4];
    let parser = tag::<_, _, ErrorKind>("a");
    let res: IResult<_, _, _> = parser(&v[..]);
    let r = res.finish();
}

#[cfg(test)]
mod tests {
    use nom::error::dbg_dmp;
}
