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

        let header_length = (ihl as usize) * 4;
        if buf.len() < header_length {
            return None;
        }

        // safe because header length is in bounds
        let (ipv4_header, _) = unsafe { buf.split_at_unchecked(header_length) };

        Some(Self { buf: ipv4_header })
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
}
