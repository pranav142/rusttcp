use crate::parse::protocol::Protocol;
use crate::parse::utils::{
    ones_complement_sum, u16_from_buf_unchecked, u16_to_buf_unchecked, u32_to_buf_unchecked,
};
use std::net::Ipv4Addr;

pub const IP_HEADER_SIZE: usize = 20;

#[derive(Debug)]
pub struct Ipv4Header {
    pub tos: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    // returns how many bytes where written to the buffer
    pub fn to_buf(&self, buf: &mut [u8], payload_length: usize) -> usize {
        if buf.len() < (IP_HEADER_SIZE) {
            panic!("Buffer is not large enough to store header")
        }

        // FIXME: Eventually we will support all protocols
        if self.protocol == Protocol::Unsupported {
            panic!("Cannot create unsupported protocol");
        }

        let flag_and_frag_offset = self.fragment_offset
            | ((self.dont_fragment as u16) << 14)
            | ((self.more_fragments as u16) << 13);

        let length = IP_HEADER_SIZE + payload_length;
        unsafe {
            *buf.get_unchecked_mut(0) = (4 << 4) | 5;
            *buf.get_unchecked_mut(1) = self.tos;

            u16_to_buf_unchecked(buf, 2, length as u16);
            u16_to_buf_unchecked(buf, 4, self.identification);
            u16_to_buf_unchecked(buf, 6, flag_and_frag_offset);

            *buf.get_unchecked_mut(8) = self.ttl;

            *buf.get_unchecked_mut(9) = self.protocol.to_bits();

            // initialize the checksum to 0
            u16_to_buf_unchecked(buf, 10, 0);

            u32_to_buf_unchecked(buf, 12, self.src_ip.to_bits());
            u32_to_buf_unchecked(buf, 16, self.dst_ip.to_bits());
        }

        let mut checksum = 0;
        for i in (0..IP_HEADER_SIZE).step_by(2) {
            let word = unsafe { u16_from_buf_unchecked(buf, i) };

            checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe {
            *buf.get_unchecked_mut(10) = (checksum >> 8) as u8;
            *buf.get_unchecked_mut(11) = (checksum & 0xFF) as u8;
        }

        IP_HEADER_SIZE
    }
}
