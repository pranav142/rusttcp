use std::{collections::HashMap, fmt::Debug, net::Ipv4Addr, vec};
use tun_tap::{Iface, Mode::Tun};

pub mod parse;

use parse::icmpv4::{Icmpv4, Icmpv4Type};
use parse::icmpv4_slice::Icmpv4Slice;
use parse::ipv4::{Ipv4Header, MIN_IP_LEN};
use parse::ipv4_slice::Ipv4HeaderSlice;
use parse::protocol::Protocol;
use parse::tcp::{MIN_TCP_HEADER_LENGTH, PsuedoHeader, TcpHeader};
use parse::tcp_slice::TcpHeaderSlice;

// TODO: Clean up magical numbers
// TODO: Add proper checks for protocols we dont support
// TODO: Add better error messages when we are unable to create a type of packet
// TODO: Potentially turn options into a struct for cleaner interactions
const MTU: usize = 1504;

fn process_ping(ip: &Ipv4HeaderSlice, icmp: &Icmpv4Slice<'_>, interface: &Iface) {
    let mut response = [0; MTU];

    if icmp.icmp_type() != Icmpv4Type::Echo {
        return;
    }

    // swap src and dst ip
    let ipv4_header = Ipv4Header {
        tos: ip.tos(),
        length: ip.length(),
        identification: ip.identification(),
        dont_fragment: ip.dont_fragment(),
        more_fragments: ip.more_fragments(),
        fragment_offset: ip.fragment_offset(),
        ttl: ip.ttl(),
        protocol: ip.protocol(),
        src_ip: ip.dst_ip(),
        dst_ip: ip.src_ip(),
    };

    let icmp_header = Icmpv4 {
        icmp_type: Icmpv4Type::EchoReply,
        code: icmp.code(),
        identifier: icmp.identifier(),
        sequence_number: icmp.sequence_number(),
        payload: icmp.payload(),
    };

    unsafe {
        *response.get_unchecked_mut(2) = 8;
    }

    ipv4_header.to_buf(&mut response[4..]);
    icmp_header.to_buf(&mut response[usize::from(4 + ipv4_header.header_length())..]);

    let result = interface.send(&response);
    match result {
        Ok(status) => {
            println!("Succesfully sent ICMP echo reply: {}", status);
        }
        Err(error) => {
            println!("Error sending ICMP echo reply: {}", error);
        }
    }
}

struct SendSeq {
    una: u32,
    nxt: u32,
    wnd: u32,
    up: u32,
    wl1: u32,
    wl2: u32,
    iss: u32,
}

struct RecvSeq {
    nxt: u32,
    wnd: u32,
    up: u32,
    irs: u32,
}

#[derive(Debug)]
enum TcpState {
    Listen,
    SynRecieved,
    Established,
}

#[derive(Debug)]
struct TcpConn {
    state: TcpState,
}

impl TcpConn {
    fn new() -> Self {
        Self {
            state: TcpState::Listen,
        }
    }

    // returns the number of bytes of the tcp response
    fn on_packet(
        &mut self,
        response: &mut [u8],
        ip: &Ipv4HeaderSlice<'_>,
        tcp: &TcpHeaderSlice<'_>,
    ) -> usize {
        match self.state {
            TcpState::Listen => {
                let seq_number = 500;
                let window = 10;

                let psuedo_header = PsuedoHeader {
                    dst_addr: ip.src_ip(),
                    src_addr: ip.dst_ip(),
                    protocol: Protocol::Tcp,
                    tcp_length: MIN_TCP_HEADER_LENGTH as u16,
                };

                let tcp_response = TcpHeader {
                    src_port: tcp.dst_port(),
                    dst_port: tcp.src_port(),
                    seq_number,
                    ack_number: tcp.seq_number() + 1,
                    cwr: false,
                    ece: false,
                    urg: false,
                    ack: true,
                    psh: false,
                    rst: false,
                    syn: true,
                    fin: false,
                    window,
                    psuedo_header,
                    urgent_pointer: 0,
                    options: &Vec::new(),
                    data: &Vec::new(),
                };

                self.state = TcpState::SynRecieved;
                tcp_response.to_buf(response);

                println!("\nResponse:\n{:?}", TcpHeaderSlice::from_buf(response));

                MIN_TCP_HEADER_LENGTH
            }
            _ => 0,
        }
    }
}

#[derive(Hash, Debug, PartialEq, Eq)]
struct Quad {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

impl Quad {
    fn from(ip: &Ipv4HeaderSlice<'_>, tcp: &TcpHeaderSlice<'_>) -> Self {
        Self {
            src_ip: ip.src_ip(),
            src_port: tcp.src_port(),
            dst_ip: ip.dst_ip(),
            dst_port: tcp.dst_port(),
        }
    }
}

struct TcpConnManager {
    conns: HashMap<Quad, TcpConn>,
}

impl TcpConnManager {
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
        }
    }

    fn process_packet(
        &mut self,
        interface: &Iface,
        ip: &Ipv4HeaderSlice<'_>,
        tcp: &TcpHeaderSlice<'_>,
    ) {
        let mut response = [0; MTU];
        let quad = Quad::from(ip, tcp);

        let connection = self.conns.entry(quad).or_insert(TcpConn::new());

        unsafe {
            *response.get_unchecked_mut(2) = 8;
        }

        let bytes = connection.on_packet(&mut response[MIN_IP_LEN + 4..], ip, tcp);

        if bytes == 0 {
            return;
        }

        let ipv4_header = Ipv4Header {
            tos: ip.tos(),
            length: (bytes + MIN_IP_LEN) as u16,
            identification: ip.identification(),
            dont_fragment: ip.dont_fragment(),
            more_fragments: ip.more_fragments(),
            fragment_offset: ip.fragment_offset(),
            ttl: ip.ttl(),
            protocol: ip.protocol(),
            src_ip: ip.dst_ip(),
            dst_ip: ip.src_ip(),
        };

        ipv4_header.to_buf(&mut response[4..]);

        println!("\nFull Response:\n {:?}", response);

        let tun_result = interface.send(&response);
        match tun_result {
            Ok(bytes_sent) => {
                println!("Successfully sent TCP message (len: {})", bytes_sent);
            }
            Err(error) => {
                println!("Failed to send TCP message: {:?}", error);
            }
        }
    }
}

// FIXME: Gross to inject the TCP connection manager here
fn process_packet(
    ip: &Ipv4HeaderSlice<'_>,
    interface: &Iface,
    buf: &[u8],
    tcp_manager: &mut TcpConnManager,
) {
    match ip.protocol() {
        Protocol::Icmp => {
            let icmp_opt = Icmpv4Slice::from_buf(buf);

            match icmp_opt {
                Some(icmp) => process_ping(ip, &icmp, interface),
                None => println!("\nFailed to create ICMP packet"),
            }
        }
        Protocol::Tcp => {
            let tcp_opt = TcpHeaderSlice::from_buf(buf);

            match tcp_opt {
                Some(tcp) => {
                    println!("\nOriginal:\n{:?}", tcp);
                    tcp_manager.process_packet(interface, ip, &tcp);
                }
                None => println!("\nFailed to create TCP packet"),
            }
            println!("Sucessfully recieved TCP packet");
        }
        _ => {
            println!("Protocol: {:?} not supported", ip.protocol());
        }
    }
}

fn main() {
    const BUF_SIZE: usize = 1504;
    let interface = Iface::new("", Tun).expect("Failed to create interface");

    let mut buf = vec![0; BUF_SIZE];
    let mut msg_id = 0;
    println!("Starting to get data");

    let mut manager = TcpConnManager::new();

    loop {
        let result = interface.recv(&mut buf);
        match result {
            Ok(byte_len) => {
                let ip_opt = Ipv4HeaderSlice::from_buf(&buf[4..byte_len]);
                match ip_opt {
                    Some(ip) => {
                        println!(
                            "\n\nSuccessfully recieved {} bytes, message ID: {}",
                            byte_len, msg_id
                        );
                        process_packet(
                            &ip,
                            &interface,
                            &buf[usize::from(4 + ip.header_length())..byte_len],
                            &mut manager,
                        );
                    }
                    None => {
                        println!("\n\nIgnoring Ipv6 Packet");
                    }
                }
            }
            Err(e) => {
                println!("Error recieving data: {}", e);
            }
        }

        msg_id += 1;
    }
}
