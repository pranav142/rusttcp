use core::panic;
use std::{fmt::{Debug, Formatter}, net::Ipv4Addr, vec, fmt};

use tun_tap::{Iface, Mode::Tun};

#[derive(Debug, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unsupported
}

impl Protocol {
    // TODO: Clean up magical numbers!
    fn from_bits(bits: u8) -> Self {
        if bits == 1 {
            return Self::Icmp;
        }

        if bits == 6 {
            return Self::Tcp;
        }
        
        if bits == 17 {
            return Self::Udp;
        }

        Self::Unsupported
    }

    fn to_bits(&self) -> u8 { 
        match self { 
            Self::Icmp => 1, 
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unsupported => 0,
        }
    }
}


// If index and index + 1 are out of bounds then this
// will lead to undefined behavior.
unsafe fn u16_from_buf_unchecked(buf: &[u8], index: usize) -> u16 {
    unsafe { 
        ((*buf.get_unchecked(index) as u16) << 8) | *buf.get_unchecked(index + 1) as u16
    }
}

// If index up to index + 3 are out of bounds then this 
// will lead to undefined behavior
unsafe fn u32_from_buf_unchecked(buf: &[u8], index: usize) -> u32 { 
    let mut total = 0 ;
    for offset in 0..4 {
        total <<= 8;
        unsafe {
            total |= *buf.get_unchecked(index + offset) as u32;
        }
    }
    total
}

const MTU: usize = 1504;
const MIN_IP_LEN: usize = 20;

struct Ipv4HeaderSlice<'a> { 
    // Maybe lets wrap this up in a struct called IpHeader
    buf: &'a [u8],
}

impl Debug for Ipv4HeaderSlice<'_> { 
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4HeaderSlice")
            .field("tos", &self.tos())
            .field("identification", &self.identification())
            .field("dont fragment", &self.dont_fragment())
            .field("more fragments", &self.more_fragments())
            .field("fragment offset", &self.fragment_offset())
            .field("ttl", &self.ttl())
            .field("checksum", &self.checksum())
            .field("ihl (bytes)", &self.header_length())
            .field("length (bytes)", &self.length())
            .field("source addr", &format_args!("{:?}", self.src_ip()))
            .field("destination addr", &format_args!("{:?}", self.dst_ip()))
            .finish()
    }
}

impl<'a> Ipv4HeaderSlice<'a> {
    // TODO: change this from a option type to a result type
    fn from_buf(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MIN_IP_LEN { 
            return None;
        }
        
        // safe because buffer length has been verified 
        let (version, ihl) = unsafe { 
            let value = *buf.get_unchecked(0);
            (value >> 4, value & 0xF)
        };

        if version != 4 { 
            return None;
        }

        if ihl < 5 { 
            return None;
        }

        let header_length = (ihl as usize) * 4;
        if buf.len() < header_length { 
            return None
        }
        
        // safe because header length is in bounds
        let (ipv4_header, _) = unsafe { 
            buf.split_at_unchecked(header_length)
        };

        Some(Self { 
            buf: ipv4_header 
        })
    }

    fn tos(&self) -> u8 { 
        unsafe { 
            *self.buf.get_unchecked(1)
        }
    }

    fn identification(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 4)
        }
    }

    fn dont_fragment(&self) -> bool { 
        let flags_and_frag = unsafe { 
            u16_from_buf_unchecked(self.buf, 6)
        };

        (flags_and_frag >> 14) & 1 == 1
    }

    fn more_fragments(&self) -> bool { 
        let flags_and_frag = unsafe { 
            u16_from_buf_unchecked(self.buf, 6)
        };

        ((flags_and_frag >> 13) & 1) == 1
    }

    fn fragment_offset(&self) -> u16 { 
        let flags_and_frag = unsafe { 
            u16_from_buf_unchecked(self.buf, 6)
        };

        flags_and_frag & 0x1FFF
    }

    fn ttl(&self) -> u8 { 
        unsafe { 
            *self.buf.get_unchecked(8)
        }
    }

    fn checksum(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 10)
        }
    }

    /// Byte length of the internet header
    fn header_length(&self) -> u8 { 
        unsafe { 
            (*self.buf.get_unchecked(0) & 0xF) * 4
        }
    }

    /// Byte length of the entire internet packet
    fn length(&self) -> u16 {
        unsafe {
            u16_from_buf_unchecked(self.buf, 2) 
        }
    }

    fn src_ip(&self) -> Ipv4Addr { 
        unsafe {
            Ipv4Addr::from_bits(u32_from_buf_unchecked(self.buf, 12))
        }
    }

    fn dst_ip(&self) -> Ipv4Addr { 
        unsafe {
            Ipv4Addr::from_bits(u32_from_buf_unchecked(self.buf, 16))
        }
    }

    fn protocol(&self) -> Protocol { 
        let protocol_bits = unsafe { 
            *self.buf.get_unchecked(9)
        };

        Protocol::from_bits(protocol_bits)
    }
}

#[derive(Debug)]
struct Ipv4Header {
    tos: u8,
    length: u16,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
    ttl: u8,
    protocol: Protocol,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    // TODO: Clean up magic numbers
    pub fn to_buf(&self, buf: &mut [u8]) {
        if buf.len() < 20 { 
            panic!("Buffer is not large enough to store header")
        }

        // FIXME: Eventually we will support all protocols
        if self.protocol == Protocol::Unsupported { 
            panic!("Cannot create unsupported protocol");
        }

        let flag_and_frag_offset = self.fragment_offset | ((self.dont_fragment as u16) << 14) | ((self.more_fragments as u16) << 13);
        let src_ip_bits = self.src_ip.to_bits();
        let dst_ip_bits = self.dst_ip.to_bits();

        unsafe {
            *buf.get_unchecked_mut(0) = (4 << 4) | 5;
            *buf.get_unchecked_mut(1) = self.tos;

            *buf.get_unchecked_mut(2) = (self.length >> 8) as u8;
            *buf.get_unchecked_mut(3) = (self.length & 0xFF) as u8;

            *buf.get_unchecked_mut(4) = (self.identification >> 8) as u8;
            *buf.get_unchecked_mut(5) = (self.identification & 0xFF) as u8;

            *buf.get_unchecked_mut(6) = (flag_and_frag_offset >> 8) as u8;
            *buf.get_unchecked_mut(7) = (flag_and_frag_offset & 0xFF) as u8;

            *buf.get_unchecked_mut(8) = self.ttl;

            *buf.get_unchecked_mut(9) = self.protocol.to_bits();
            
            // initialize the checksum to 0
            *buf.get_unchecked_mut(10) = 0;
            *buf.get_unchecked_mut(11) = 0;

            *buf.get_unchecked_mut(12) = (src_ip_bits >> 24) as u8;
            *buf.get_unchecked_mut(13) = ((src_ip_bits >> 16) & 0xFF) as u8;
            *buf.get_unchecked_mut(14) = ((src_ip_bits >> 8) & 0xFF) as u8;
            *buf.get_unchecked_mut(15) = (src_ip_bits & 0xFF) as u8;

            *buf.get_unchecked_mut(16) = (dst_ip_bits >> 24) as u8;
            *buf.get_unchecked_mut(17) = ((dst_ip_bits >> 16) & 0xFF) as u8;
            *buf.get_unchecked_mut(18) = ((dst_ip_bits >> 8) & 0xFF) as u8;
            *buf.get_unchecked_mut(19) = (dst_ip_bits & 0xFF) as u8;
        }

        let mut checksum = 0;
        for i in (0..20).step_by(2) { 
            let word = unsafe { 
                u16_from_buf_unchecked(buf, i)
            };

            checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe { 
            *buf.get_unchecked_mut(10) = (checksum >> 8) as u8;
            *buf.get_unchecked_mut(11) = (checksum & 0xFF) as u8;
        }
    }
}

fn ones_complement_sum(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    let is_overflow = (sum & 0x10000) > 0;

    if is_overflow {
        sum &= !(0x10000);
        sum += 1;
    }

    sum as u16
}

struct Icmpv4Slice<'a> {
    buf: &'a [u8]
}

#[derive(Debug, PartialEq, Eq)]
enum Icmpv4Type { 
    Echo,
    EchoReply,
}

const MIN_ICMP_HEADER_SIZE: usize = 8;
const ECHO_TYPE: u8 = 8;
const ECHO_REPLY_TYPE: u8 = 0;

impl<'a> Icmpv4Slice<'a> { 
    fn from_buf(buf: &'a [u8]) -> Option<Self> { 
        if buf.len() < MIN_ICMP_HEADER_SIZE { 
            return None; 
        }
    
        // safe because of buffer size check
        let icmp_type = unsafe { 
            *buf.get_unchecked(0)
        };

        // FIXME: Add support for other ICMP types
        if icmp_type != ECHO_TYPE && icmp_type != ECHO_REPLY_TYPE { 
            return None;
        }

        Some(Self { 
            buf
        })
    }

    fn icmp_type(&self) -> Icmpv4Type { 
        let type_bits = unsafe { 
            *self.buf.get_unchecked(0)
        };

        if type_bits ==  ECHO_TYPE { 
            return Icmpv4Type::Echo;
        }

        Icmpv4Type::EchoReply
    }

    fn code(&self) -> u8 { 
        unsafe {
            *self.buf.get_unchecked(1)
        }
    }

    fn identifier(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 4)
        }
    }

    fn sequence_number(&self) -> u16 {
        unsafe {
            u16_from_buf_unchecked(self.buf, 6)
        }
    } 
    
    fn checksum(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 2)
        }
    }

    fn payload(&self) -> &'a [u8] { 
        &self.buf[MIN_ICMP_HEADER_SIZE..]
    }
}

struct Icmpv4<'a> { 
    icmp_type: Icmpv4Type,
    code: u8,
    identifier: u16,
    sequence_number: u16,
    payload: &'a [u8],
}

impl Icmpv4<'_> { 
    fn to_buf(&self, buf: &mut [u8]) { 
        if buf.len() < (MIN_ICMP_HEADER_SIZE + self.payload.len()) { 
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
        let icmp_length = MIN_ICMP_HEADER_SIZE + self.payload.len();

        // this checksum calculation is wrong
        for i in (0..icmp_length).step_by(2) { 
            let word = unsafe { 
                u16_from_buf_unchecked(buf, i)
            };
            checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe {
            *buf.get_unchecked_mut(2) = (checksum >> 8) as u8;
            *buf.get_unchecked_mut(3) = (checksum & 0xFF) as u8;
        }

    }
}

impl Debug for Icmpv4Slice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { 
        f.debug_struct("Icmpv4HeaderSlice")
            .field("type", &format_args!("{:?}", self.icmp_type()))
            .field("code", &self.code())
            .field("identifier", &self.identifier())
            .field("sequence number", &self.sequence_number())
            .field("checksum", &self.checksum())
            .field("payload", &self.payload()) 
            .finish()
    }
} 

fn process_ping(ip: &Ipv4HeaderSlice, icmp: &Icmpv4Slice<'_>, interface: &Iface) {
    let mut response = [0; MTU];

    if icmp.icmp_type() != Icmpv4Type::Echo { 
        return;
    } 

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

    // need to copy over the pay load?!
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
    icmp_header.to_buf(&mut response[24..]);


    let result = interface.send(&response);
    match result {
        Ok(status) => {
            println!("Succesfully sent ICMP echo reply: {}", status);
        },
        Err(error) => {
            println!("Error sending ICMP echo reply: {}", error);
        }
    }
}

fn process_packet(ip: &Ipv4HeaderSlice<'_>, interface: &Iface, buf: &[u8]) {

    match ip.protocol() {
        Protocol::Icmp => {
            let icmp_buf = &buf[usize::from(ip.header_length())..];
            let icmp_opt = Icmpv4Slice::from_buf(icmp_buf);

            match icmp_opt { 
                Some(icmp) => { 
                    process_ping(ip, &icmp, interface)
                },
                None => println!("Failed to create ICMP packet"),
            }
        },
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

    loop {
        let result = interface.recv(&mut buf);
        match result {
            Ok(byte_len) => {
                let ip_opt = Ipv4HeaderSlice::from_buf(&buf[4..byte_len]);
                match ip_opt { 
                    Some(ip) => {
                        println!("\n\nSuccessfully recieved {} bytes, message ID: {}", byte_len, msg_id);
                        process_packet(&ip, &interface, &buf[4..byte_len]);
                    }
                    None => {
                        println!("\n\nIgnoring Packet");
                    }
                }
            },
            Err(e) => {
                println!("Error recieving data: {}", e);
            }
        }
        
        msg_id += 1;
    }
}
