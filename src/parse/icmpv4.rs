use crate::parse::utils::{ones_complement_sum, u16_from_buf_unchecked};

pub const ICMP_HEADER_SIZE: usize = 8;
pub const ECHO_TYPE: u8 = 8;
pub const ECHO_REPLY_TYPE: u8 = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum Icmpv4Type {
    Echo,
    EchoReply,
}

impl Icmpv4Type {
    // turns the type into its valid bit representation
    // in the Icmpv4 header.
    fn to_bits(&self) -> u8 {
        match self {
            Icmpv4Type::Echo => ECHO_TYPE,
            Icmpv4Type::EchoReply => ECHO_REPLY_TYPE,
        }
    }
}

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

        unsafe {
            *buf.get_unchecked_mut(0) = self.icmp_type.to_bits();
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
                *buf.get_unchecked_mut(i + ICMP_HEADER_SIZE) = *val;
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

    pub fn length(&self) -> usize {
        ICMP_HEADER_SIZE + self.payload.len()
    }
}
