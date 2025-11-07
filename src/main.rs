use parse::icmpv4_slice::Icmpv4Slice;
use parse::ipv4_header_slice::Ipv4HeaderSlice;
use parse::protocol::Protocol;

use crate::parse::tcp_slice::TcpHeaderSlice;
use crate::parse::ipv4::{IpPayload, Ipv4Packet};
use crate::tcp::TcpConnManager;
use crate::tun_interface::TunInterface;
use icmpv4::process_icmpv4;

mod icmpv4;
mod parse;
mod tcp;
mod tun_interface;

// TODO: Clean up magical numbers
// TODO: Add proper checks for protocols we dont support
// TODO: Add better error messages when we are unable to create a type of packet
// TODO: We seriously need much better error messages

struct Processor {
    tcp_manager: TcpConnManager,
}

impl Processor {
    fn new() -> Self {
        let tcp_manager = TcpConnManager::new();

        Self{
            tcp_manager,
        }
    }

    fn process_ipv4<'a>(&mut self, ip: &Ipv4HeaderSlice<'a>) -> Option<Ipv4Packet<'a>> {
        let payload = match ip.protocol() {
            Protocol::Icmp => {
                let icmp = Icmpv4Slice::from_buf(ip.payload())?;
                let reply = process_icmpv4(&icmp)?;
                Some(IpPayload::Icmp(reply))
            }
            Protocol::Tcp => {
                let tcp = TcpHeaderSlice::from_buf(ip.payload())?;
                let reply = self.tcp_manager.process_packet(ip, &tcp)?;
                Some(IpPayload::Tcp(reply))
            }
            Protocol::Udp | Protocol::Unsupported => {
                println!("Protocol: {:?} not supported", ip.protocol());
                None
            }
        }?;

        Some(Ipv4Packet::new(ip.reply(), payload))
    }
}

fn main() {
    let mut interface = TunInterface::new();
    let mut processor = Processor::new();
    println!("Starting to get data");

    loop {
        let result = interface.recv();

        match result {
            Ok((ip_packet, tx)) => {
                let Some(response) = processor.process_ipv4(&ip_packet) else {
                    continue;
                };

                if let Err(error) = tx.send(&response) {
                    println!("Error sending packet: {}", error);
                    continue;
                };

                println!("succesfully sent response");
            }
            Err(error) => {
                println!("Error recieving packet: {}", error);
            }
        }
    }
}
