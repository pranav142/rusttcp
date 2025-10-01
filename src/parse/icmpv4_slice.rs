use crate::parse::icmpv4::{ECHO_REPLY_TYPE, ECHO_TYPE, ICMP_HEADER_SIZE, Icmpv4Type};
use crate::parse::utils::u16_from_buf_unchecked;
use std::{
    fmt,
    fmt::{Debug, Formatter},
};

pub struct Icmpv4Slice<'a> {
    buf: &'a [u8],
}

impl<'a> Icmpv4Slice<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < ICMP_HEADER_SIZE {
            return None;
        }

        // safe because of buffer size check
        let icmp_type = unsafe { *buf.get_unchecked(0) };

        // FIXME: Add support for other ICMP types
        if icmp_type != ECHO_TYPE && icmp_type != ECHO_REPLY_TYPE {
            return None;
        }

        Some(Self { buf })
    }

    pub fn icmp_type(&self) -> Icmpv4Type {
        let type_bits = unsafe { *self.buf.get_unchecked(0) };

        if type_bits == ECHO_TYPE {
            return Icmpv4Type::Echo;
        }

        Icmpv4Type::EchoReply
    }

    pub fn code(&self) -> u8 {
        unsafe { *self.buf.get_unchecked(1) }
    }

    pub fn identifier(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 4) }
    }

    pub fn sequence_number(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 6) }
    }

    pub fn checksum(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 2) }
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.buf[ICMP_HEADER_SIZE..]
    }
}

impl Debug for Icmpv4Slice<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Icmpv4HeaderSlice")
            .field("type", &format_args!("{:?}", self.icmp_type()))
            .field("code", &self.code())
            .field("identifier", &self.identifier())
            .field("sequence number", &self.sequence_number())
            .field("checksum", &self.checksum())
            .field("payload", &self.payload())
            .finish()
    }
}
