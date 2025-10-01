use crate::parse::utils::{ones_complement_sum, u16_from_buf_unchecked};

#[derive(Debug, PartialEq, Eq)]
pub enum Icmpv4Type {
    Echo,
    EchoReply,
}

pub const ICMP_HEADER_SIZE: usize = 8;
pub const ECHO_TYPE: u8 = 8;
pub const ECHO_REPLY_TYPE: u8 = 0;

pub struct Icmpv4<'a> {
    pub icmp_type: Icmpv4Type,
    pub code: u8,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: &'a [u8],
}

impl Icmpv4<'_> {
    pub fn to_buf(&self, buf: &mut [u8]) {
        if buf.len() < (ICMP_HEADER_SIZE + self.payload.len()) {
            panic!("Provided buffer is not large enough for ICMP v4 header and payload");
        }

        let protocol = {
            if self.icmp_type == Icmpv4Type::Echo {
                ECHO_TYPE
            } else {
                ECHO_REPLY_TYPE
            }
        };

        unsafe {
            *buf.get_unchecked_mut(0) = protocol;
            *buf.get_unchecked_mut(1) = self.code;

            // initially set the check sum to 0
            *buf.get_unchecked_mut(2) = 0;
            *buf.get_unchecked_mut(3) = 0;

            *buf.get_unchecked_mut(4) = (self.identifier >> 8) as u8;
            *buf.get_unchecked_mut(5) = (self.identifier & 0xFF) as u8;

            *buf.get_unchecked_mut(6) = (self.sequence_number >> 8) as u8;
            *buf.get_unchecked_mut(7) = (self.sequence_number & 0xFF) as u8;
        }

        for (i, val) in self.payload.iter().enumerate() {
            unsafe {
                *buf.get_unchecked_mut(i + 8) = *val;
            }
        }

        let mut checksum = 0;
        let icmp_length = ICMP_HEADER_SIZE + self.payload.len();

        // FIXME: this checksum calculation is wrong
        // when the length is odd we need to do some padding
        for i in (0..icmp_length).step_by(2) {
            let word = unsafe { u16_from_buf_unchecked(buf, i) };
            checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe {
            *buf.get_unchecked_mut(2) = (checksum >> 8) as u8;
            *buf.get_unchecked_mut(3) = (checksum & 0xFF) as u8;
        }
    }
}
