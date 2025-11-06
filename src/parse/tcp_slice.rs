use crate::parse::tcp::MIN_TCP_HEADER_LENGTH;
use crate::parse::utils::{u16_from_buf_unchecked, u32_from_buf_unchecked};
use std::fmt::{self, Debug, Formatter};

pub struct TcpHeaderSlice<'a> {
    buf: &'a [u8],
}

impl<'a> TcpHeaderSlice<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MIN_TCP_HEADER_LENGTH {
            return None;
        }

        let data_offset = unsafe { *buf.get_unchecked(12) >> 4 };

        if buf.len() < usize::from(data_offset * 4) {
            return None;
        }

        Some(Self { buf })
    }

    pub fn src_port(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 0) }
    }

    pub fn dst_port(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 2) }
    }

    pub fn seq_number(&self) -> u32 {
        unsafe { u32_from_buf_unchecked(self.buf, 4) }
    }

    pub fn ack_number(&self) -> u32 {
        unsafe { u32_from_buf_unchecked(self.buf, 8) }
    }

    // 32 bit words in TCP header including Options
    pub fn data_offset(&self) -> u8 {
        unsafe { *self.buf.get_unchecked(12) >> 4 }
    }

    pub fn cwr(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 7)) > 1 }
    }

    pub fn ece(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 6)) > 1 }
    }

    pub fn urg(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 5)) > 1 }
    }

    pub fn ack(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 4)) > 1 }
    }

    pub fn psh(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 3)) > 1 }
    }

    pub fn rst(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 2)) > 1 }
    }

    pub fn syn(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & (1 << 1)) > 1 }
    }

    pub fn fin(&self) -> bool {
        unsafe { (*self.buf.get_unchecked(13) & 1) == 1 }
    }

    pub fn window(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 14) }
    }

    pub fn checksum(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 16) }
    }

    pub fn urgent_pointer(&self) -> u16 {
        unsafe { u16_from_buf_unchecked(self.buf, 18) }
    }

    fn options(&self) -> &'a [u8] {
        let data_offset = self.data_offset();
        let data_offset = usize::from(data_offset * 4);

        &self.buf[MIN_TCP_HEADER_LENGTH..data_offset]
    }

    fn data(&self) -> &'a [u8] {
        let data_offset = unsafe { *self.buf.get_unchecked(12) >> 4 };
        let data_offset = usize::from(data_offset) * 4;

        &self.buf[data_offset..]
    }
}

impl Debug for TcpHeaderSlice<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpHeaderSlice")
            .field("source port", &self.src_port())
            .field("destination port", &self.dst_port())
            .field("sequence number", &self.seq_number())
            .field("acknowledgment number", &self.ack_number())
            .field("flag (cwr)", &self.cwr())
            .field("flag (ece)", &self.ece())
            .field("flag (urg)", &self.urg())
            .field("flag (ack)", &self.ack())
            .field("flag (psh)", &self.psh())
            .field("flag (rst)", &self.rst())
            .field("flag (syn)", &self.syn())
            .field("flag (fin)", &self.fin())
            .field("checksum", &self.checksum())
            .field("data offset", &self.data_offset())
            .field("window", &self.window())
            .field("urgent pointer", &self.urgent_pointer())
            .finish()
    }
}
