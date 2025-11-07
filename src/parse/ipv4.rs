use crate::parse::icmpv4::Icmpv4;
use crate::parse::ipv4_header::Ipv4Header;
use crate::parse::tcp::TcpHeader;

pub enum IpPayload<'a> {
    Icmp(Icmpv4<'a>),
    Tcp(TcpHeader<'a>),
}

pub struct Ipv4Packet<'a> {
    header: Ipv4Header,
    payload: IpPayload<'a>,
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(header: Ipv4Header, payload: IpPayload<'a>) -> Self {
        Self { header, payload }
    }

    pub fn to_buf(&self, buf: &mut [u8]) {
        match &self.payload {
            IpPayload::Icmp(icmpv4) => {
                let len = self.header.to_buf(buf, icmpv4.length());
                icmpv4.to_buf(&mut buf[len..]);
            }
            IpPayload::Tcp(tcp) => {
                let len = self.header.to_buf(buf, tcp.length());
                tcp.to_buf(&mut buf[len..]);
            }
        }
    }
}
