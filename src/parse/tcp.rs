use crate::parse::protocol::Protocol;
use crate::parse::utils::{
    ones_complement_sum, u16_from_buf_unchecked, u16_to_buf_unchecked, u32_to_buf_unchecked,
};
use std::{
    fmt::{self, Debug, Formatter},
    net::Ipv4Addr,
};

pub const MIN_TCP_HEADER_LENGTH: usize = 20;

pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window: u16,
    pub psuedo_header: PsuedoHeader,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub data: &'a [u8],
}

impl Debug for TcpHeader<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpHeaderSlice")
            .field("source port", &self.src_port)
            .field("destination port", &self.dst_port)
            .field("sequence number", &self.seq_number)
            .field("acknowledgment number", &self.ack_number)
            .field("flag (cwr)", &self.cwr)
            .field("flag (ece)", &self.ece)
            .field("flag (urg)", &self.urg)
            .field("flag (ack)", &self.ack)
            .field("flag (psh)", &self.psh)
            .field("flag (rst)", &self.rst)
            .field("flag (syn)", &self.syn)
            .field("flag (fin)", &self.fin)
            .field("window", &self.window)
            .field("urgent pointer", &self.urgent_pointer)
            .finish()
    }
}

impl TcpHeader<'_> {
    // FIXME: let us have this return a error
    // TODO: need to have this sudo header shit
    pub fn to_buf(&self, buf: &mut [u8]) {
        let tcp_size = MIN_TCP_HEADER_LENGTH + self.options.len() + self.data.len();

        if buf.len() < (tcp_size) {
            return;
        }

        let data_offset = (MIN_TCP_HEADER_LENGTH + self.options.len()) / 4;
        unsafe {
            u16_to_buf_unchecked(buf, 0, self.src_port);

            u16_to_buf_unchecked(buf, 2, self.dst_port);

            u32_to_buf_unchecked(buf, 4, self.seq_number);
            u32_to_buf_unchecked(buf, 8, self.ack_number);

            *buf.get_unchecked_mut(12) = (data_offset << 4) as u8;

            *buf.get_unchecked_mut(13) = 0;
            *buf.get_unchecked_mut(13) |= (self.cwr as u8) << 7;
            *buf.get_unchecked_mut(13) |= (self.ece as u8) << 6;
            *buf.get_unchecked_mut(13) |= (self.urg as u8) << 5;
            *buf.get_unchecked_mut(13) |= (self.ack as u8) << 4;
            *buf.get_unchecked_mut(13) |= (self.psh as u8) << 3;
            *buf.get_unchecked_mut(13) |= (self.rst as u8) << 2;
            *buf.get_unchecked_mut(13) |= (self.syn as u8) << 1;
            *buf.get_unchecked_mut(13) |= self.fin as u8;

            u16_to_buf_unchecked(buf, 14, self.window);

            // initialize the checksum to zero
            u16_to_buf_unchecked(buf, 16, 0);

            u16_to_buf_unchecked(buf, 18, self.urgent_pointer);
        }

        let mut cur_index = MIN_TCP_HEADER_LENGTH;

        for val in self.options.iter() {
            unsafe {
                *buf.get_unchecked_mut(cur_index) = *val;
                cur_index += 1;
            }
        }

        for val in self.data.iter() {
            unsafe {
                *buf.get_unchecked_mut(cur_index) = *val;
                cur_index += 1;
            }
        }

        let src_addr = self.psuedo_header.src_addr.to_bits();
        let dst_addr = self.psuedo_header.dst_addr.to_bits();

        // Required to calculate the checksum of a psuedo header
        let mut checksum = ones_complement_sum((src_addr >> 16) as u16, (src_addr & 0xFFFF) as u16);
        checksum = ones_complement_sum(checksum, (dst_addr >> 16) as u16);
        checksum = ones_complement_sum(checksum, (dst_addr & 0xFFFF) as u16);
        checksum = ones_complement_sum(checksum, self.psuedo_header.protocol.to_bits() as u16);
        checksum = ones_complement_sum(checksum, self.psuedo_header.tcp_length);

        for i in (0..cur_index - 1).step_by(2) {
            let word = unsafe { u16_from_buf_unchecked(buf, i) };
            checksum = ones_complement_sum(checksum, word);
        }

        // if there is a odd number of octets add the last octet
        // with 0 padding to the right
        if cur_index % 2 == 1 {
            let word = unsafe { (*buf.get_unchecked_mut(cur_index - 1) as u16) << 8 };
            checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe {
            u16_to_buf_unchecked(buf, 16, checksum);
        }
    }

    /// returns the total length of the TCP Header
    pub fn length(&self) -> usize {
        MIN_TCP_HEADER_LENGTH + self.options.len() + self.data.len()
    }
}

pub struct PsuedoHeader {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub protocol: Protocol,
    pub tcp_length: u16,
}
