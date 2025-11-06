use parse::icmpv4_slice::Icmpv4Slice;
use parse::ipv4_header_slice::Ipv4HeaderSlice;
use parse::protocol::Protocol;

use crate::parse::ipv4::{IpPayload, Ipv4Packet};
use crate::tun_interface::TunInterface;
use icmpv4::process_icmpv4;

mod icmpv4;
mod parse;
mod tun_interface;
// mod tcp;

// TODO: Clean up magical numbers
// TODO: Add proper checks for protocols we dont support
// TODO: Add better error messages when we are unable to create a type of packet
// TODO: We seriously need much better error messages

fn process_ipv4<'a>(ip: &Ipv4HeaderSlice<'a>) -> Option<Ipv4Packet<'a>> {
    let payload = match ip.protocol() {
        Protocol::Icmp => {
            let icmp = Icmpv4Slice::from_buf(ip.payload())?;
            let reply = process_icmpv4(&icmp)?;
            Some(IpPayload::Icmp(reply))
        }
        Protocol::Tcp => {
            // let tcp_opt = TcpHeaderSlice::from_buf(buf);

            // match tcp_opt {
            //     Some(tcp) => {
            //         println!("\nOriginal:\n{:?}", tcp);
            //         tcp_manager.process_packet(interface, ip, &tcp);
            //     }
            //     None => println!("\nFailed to create TCP packet"),
            // }
            // println!("Sucessfully recieved TCP packet");
            None
        }
        Protocol::Udp | Protocol::Unsupported => {
            println!("Protocol: {:?} not supported", ip.protocol());
            None
        }
    }?;

    Some(Ipv4Packet::new(ip.reply(), payload))
}

fn main() {
    let mut interface = TunInterface::new();
    println!("Starting to get data");

    loop {
        let result = interface.recv();

        match result {
            Ok((ip_packet, tx)) => {
                let Some(response) = process_ipv4(&ip_packet) else {
                    continue;
                };

                if let Err(error) = tx.send(&response) {
                    println!("Error sending packet accross buffer: {}", error)
                };
            }
            Err(error) => {
                println!("Error recieving from tun buffer: {}", error);
            }
        }
    }
}
