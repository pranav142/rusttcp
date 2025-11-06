use crate::parse::{ipv4::Ipv4Packet, ipv4_header_slice::Ipv4HeaderSlice};
use tun_tap::{Iface, Mode::Tun};

const MTU: usize = 1504;

type Result<T> = std::result::Result<T, InterfaceError>;

pub struct TunInterface {
    iface: Iface,
    buf: Vec<u8>,
}

impl TunInterface {
    pub fn new() -> Self {
        let iface = Iface::new("", Tun).expect("Failed to create TUN interface");
        let buf = vec![0; MTU];

        TunInterface { iface, buf }
    }

    pub fn recv<'a>(&'a mut self) -> Result<(Ipv4HeaderSlice<'a>, Tx<'a>)> {
        let _ = self.iface.recv(&mut self.buf)?;
        let packet = Ipv4HeaderSlice::from_buf(&self.buf[4..]).ok_or(InterfaceError::InvalidIpPacket)?; 
        let transmit = Tx { iface: &self.iface };
        Ok((packet, transmit))
    }
}

pub struct Tx<'a> {
    iface: &'a Iface
}

impl Tx<'_> { 
    pub fn send(&self, packet: &Ipv4Packet) -> Result<()> {
        let mut buf = [0; MTU];

        // TUN Meta Data 
        unsafe {
            *buf.get_unchecked_mut(2) = 8;
        }

        packet.to_buf(&mut buf[4..]);
        self.iface.send(&buf)?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum InterfaceError {
    TunError,
    InvalidIpPacket,
}

impl std::fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceError::TunError => f.debug_struct("InterfaceError::TunError").finish(),
            InterfaceError::InvalidIpPacket =>f.debug_struct("InterfaceError::InvalidIpPacket").finish()
        }
    }
}

impl From<std::io::Error> for InterfaceError {
    fn from(_: std::io::Error) -> Self {
        InterfaceError::TunError
    }
}

impl std::error::Error for InterfaceError {}
