use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::parse::ipv4_header_slice::Ipv4HeaderSlice;
use crate::parse::protocol::Protocol;
use crate::parse::tcp::{MIN_TCP_HEADER_LENGTH, PsuedoHeader, TcpHeader};
use crate::parse::tcp_slice::TcpHeaderSlice;

#[derive(Default, Debug)]
struct SendSeq {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u32,
    /// send urgent pointer
    up: u32,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

#[derive(Default, Debug)]
struct RecvSeq {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u32,
    /// receive urgent pointer
    up: u32,
    /// initial receive sequence number
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
    rcv: RecvSeq,
    snd: SendSeq,
}

impl TcpConn {
    fn new() -> Self {
        Self {
            state: TcpState::Listen,
            rcv: RecvSeq::default(),
            snd: SendSeq::default(),
        }
    }

    // TODO: Need to generate a random ISN
    fn generate_isn(&self) -> u32 {
        100000
    }

    // returns the number of bytes of the tcp response
    // right now we are returning the number of bytes of the TCP response
    fn on_packet<'a>(
        &mut self,
        ip: &Ipv4HeaderSlice<'a>,
        tcp: &TcpHeaderSlice<'a>,
    ) -> Option<TcpHeader<'a>> {
        match self.state {
            TcpState::Listen => {
                if !tcp.syn() {
                    return None;
                }

                let seq_number = self.generate_isn();
                let window = 5000;

                self.snd.iss = seq_number;
                self.snd.una = seq_number;
                self.snd.nxt = seq_number + 1;

                self.rcv.irs = tcp.seq_number();
                self.rcv.nxt = tcp.seq_number() + 1;

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
                    options: &[],
                    data: &[],
                };

                self.state = TcpState::SynRecieved;

                Some(tcp_response)
            }
            TcpState::SynRecieved => {
                if !tcp.ack() {
                    return None;
                }

                if tcp.ack_number() != self.snd.nxt {
                    return None;
                }

                self.state = TcpState::Established;
                None
            }
            _ => None,
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

pub struct TcpConnManager {
    conns: HashMap<Quad, TcpConn>,
}

impl TcpConnManager {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
        }
    }

    pub fn process_packet<'a>(
        &mut self,
        ip: &Ipv4HeaderSlice<'a>,
        tcp: &TcpHeaderSlice<'a>,
    ) -> Option<TcpHeader<'a>> {
        let quad = Quad::from(ip, tcp);

        // TODO: For now accept all connections
        let connection = self.conns.entry(quad).or_insert(TcpConn::new());

        connection.on_packet(ip, tcp)
    }
}
