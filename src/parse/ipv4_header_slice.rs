use crate::parse::ipv4_header::Ipv4Header;
use crate::parse::protocol::Protocol;
use crate::parse::utils::{u16_from_buf_unchecked, u32_from_buf_unchecked};
use std::{
    fmt,
    fmt::{Debug, Formatter},
    net::Ipv4Addr,
};

const MIN_IP_LEN: usize = 20;

pub struct Ipv4HeaderSlice<'a> {
    // Maybe lets wrap this up in a struct called IpHeader
    buf: &'a [u8],
}

impl Debug for Ipv4HeaderSlice<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4HeaderSlice")
            .field("tos", &self.tos())
            .field("identification", &self.identification())
            .field("dont fragment", &self.dont_fragment())
            .field("more fragments", &self.more_fragments())
            .field("fragment offset", &self.fragment_offset())
            .field("ttl", &self.ttl())
            .field("checksum", &self.checksum())
            .field("ihl (bytes)", &self.header_length())
            .field("length (bytes)", &self.length())
            .field("source addr", &format_args!("{:?}", self.src_ip()))
            .field("destination addr", &format_args!("{:?}", self.dst_ip()))
            .finish()
    }
}

impl<'a> Ipv4HeaderSlice<'a> {
    // TODO: change this from a option type to a result type
    pub fn from_buf(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MIN_IP_LEN {
            return None;
        }

        // safe because buffer length has been verified
        let (version, ihl) = unsafe {
            let value = *buf.get_unchecked(0);
            (value >> 4, value & 0xF)
        };

        if version != 4 {
            return None;
        }

        if ihl < 5 {
            return None;
        }

        let length = unsafe { u16_from_buf_unchecked(buf, 2) };
        if buf.len() < usize::from(length) {
            println!("buf of length: {:?} is not large for ip packet of length {:?}", buf.len(), length);
            return None;
        }

        Some(Self { buf })
    }

    // should be able to take any arbitrary data and fill it up
    pub fn reply(&self) -> Ipv4Header {
        Ipv4Header {
            tos: self.tos(),
            identification: self.identification(),
            dont_fragment: self.dont_fragment(),
            more_fragments: self.more_fragments(),
            fragment_offset: self.fragment_offset(),
            ttl: self.ttl(),
            protocol: self.protocol(),
            src_ip: self.dst_ip(),
            dst_ip: self.src_ip(),
        }
    }

    pub fn tos(&self) -> u8 {
        unsafe { *self.buf.get_unchecked(1) }
    }

    pub fn identification(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 4) }
    }

    pub fn dont_fragment(&self) -> bool {
        let flags_and_frag = unsafe { u16_from_buf_unchecked(self.buf, 6) };

        (flags_and_frag >> 14) & 1 == 1
    }

    pub fn more_fragments(&self) -> bool {
        let flags_and_frag = unsafe { u16_from_buf_unchecked(self.buf, 6) };

        ((flags_and_frag >> 13) & 1) == 1
    }

    pub fn fragment_offset(&self) -> u16 {
        let flags_and_frag = unsafe { u16_from_buf_unchecked(self.buf, 6) };

        flags_and_frag & 0x1FFF
    }

    pub fn ttl(&self) -> u8 {
        unsafe { *self.buf.get_unchecked(8) }
    }

    pub fn checksum(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 10) }
    }

    /// Byte length of the internet header
    pub fn header_length(&self) -> u8 {
        unsafe { (*self.buf.get_unchecked(0) & 0xF) * 4 }
    }

    /// Byte length of the entire internet packet
    pub fn length(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 2) }
    }

    pub fn src_ip(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr::from_bits(u32_from_buf_unchecked(self.buf, 12)) }
    }

    pub fn dst_ip(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr::from_bits(u32_from_buf_unchecked(self.buf, 16)) }
    }

    pub fn protocol(&self) -> Protocol {
        let protocol_bits = unsafe { *self.buf.get_unchecked(9) };

        Protocol::from_bits(protocol_bits)
    }

    fn payload_length(&self) -> usize {
        usize::from(self.length()) - usize::from(self.header_length())
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.buf[usize::from(self.header_length())
            ..(usize::from(self.header_length()) + self.payload_length())]
    }
}
