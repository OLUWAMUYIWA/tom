use crate::de::tcp::{TcpHeader, TcpSegment};
use bytes::BytesMut;


fn ser<'t>(seg: &TcpSegment) -> BytesMut {
	let mut b = BytesMut::new();
	b
}