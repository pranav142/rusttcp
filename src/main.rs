use core::panic;
use std::{fmt::{self, Debug, Formatter}, net::Ipv4Addr, vec};

// TODO: Clean up magical numbers
// TODO: Add proper checks for protocols we dont support
// TODO: Add better error messages when we are unable to create a type of packet
// TODO: Better length slicing? this way we can precisely give a Buffer range that is exactly the
// size of the packet rather than the entire buffer. This will lead to cleaner debugging
// TODO: Potentially turn options into a struct for cleaner interactions

use tun_tap::{Iface, Mode::Tun};

#[derive(Debug, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unsupported
}

impl Protocol {
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

    fn header_length(&self) -> u16 { 
        20
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

const ICMP_HEADER_SIZE: usize = 8;
const ECHO_TYPE: u8 = 8;
const ECHO_REPLY_TYPE: u8 = 0;

impl<'a> Icmpv4Slice<'a> { 
    fn from_buf(buf: &'a [u8]) -> Option<Self> { 
        if buf.len() < ICMP_HEADER_SIZE { 
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
        &self.buf[ICMP_HEADER_SIZE..]
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
        },
        Err(error) => {
            println!("Error sending ICMP echo reply: {}", error);
        }
    }
}

fn process_packet(ip: &Ipv4HeaderSlice<'_>, interface: &Iface, buf: &[u8]) {
    match ip.protocol() {
        Protocol::Icmp => {
            let icmp_opt = Icmpv4Slice::from_buf(buf);

            match icmp_opt { 
                Some(icmp) => { 
                    process_ping(ip, &icmp, interface)
                },
                None => println!("\nFailed to create ICMP packet"),
            }
        },
        Protocol::Tcp => {
            let tcp_opt = TcpHeaderSlice::from_buf(buf);

            match tcp_opt {
                Some(tcp) => { 
                    let mut tmp = [0; MTU + 4];

                    let header = TcpHeader { 
                        src_port: tcp.src_port(), 
                        dst_port: tcp.dst_port(), 
                        seq_number: tcp.seq_number(), 
                        ack_number: tcp.ack_number(),
                        cwr: tcp.cwr(), 
                        ece: tcp.ece(), 
                        urg: tcp.urg(), 
                        ack: tcp.ack(), 
                        psh: tcp.psh(),
                        rst: tcp.rst(), 
                        syn: tcp.syn(), 
                        fin: tcp.fin(), 
                        window: tcp.window(), 
                        psuedo_header: PsuedoHeader::from_ip(ip),
                        urgent_pointer: tcp.urgent_pointer(), 
                        options: tcp.options(),
                        data: tcp.data(),
                    }; 
                    header.to_buf(&mut tmp);
                    
                    println!("\nOriginal:\n{:?}", tcp);
                    println!("\nConstructed:\n{:?}", TcpHeaderSlice::from_buf(&tmp));

                }, 
                None => println!("\nFailed to create TCP packet"),
            }
            println!("Sucessfully recieved TCP packet");

        },
        _ => {
            println!("Protocol: {:?} not supported", ip.protocol());
        }
    }
}

struct TcpHeaderSlice<'a> { 
    buf: &'a [u8]
}

const MIN_TCP_HEADER_LENGTH: usize = 20;

impl<'a> TcpHeaderSlice<'a> { 
    fn from_buf(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MIN_TCP_HEADER_LENGTH { 
            return None;
        }

        let data_offset = unsafe { 
            *buf.get_unchecked(12) >> 4
        };

        if buf.len() < usize::from(data_offset * 4)  { 
            return None;
        }

        Some(Self {
            buf
        })
    }

    fn src_port(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 0)
        }
    }

    fn dst_port(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 2)
        }
    }

    fn seq_number(&self) -> u32 {
        unsafe { 
            u32_from_buf_unchecked(self.buf, 4)
        }
    }

    fn ack_number(&self) -> u32 { 
        unsafe { 
            u32_from_buf_unchecked(self.buf, 8)
        }
    }

    // 32 bit words in TCP header including Options
    fn data_offset(&self) -> u8 { 
        unsafe { 
            *self.buf.get_unchecked(12) >> 4
        }
    }

    fn cwr(&self) -> bool { 
        unsafe {
            (*self.buf.get_unchecked(13) & (1 << 7)) > 1
        }
    }

    fn ece(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 6)) > 1
        }
    }

    fn urg(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 5)) > 1
        }
    }

    fn ack(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 4)) > 1
        }

    }

    fn psh(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 3)) > 1
        }

    }

    fn rst(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 2)) > 1
        }

    }

    fn syn(&self) -> bool { 
        unsafe { 
            (*self.buf.get_unchecked(13) & (1 << 1)) > 1
        }

    }

    fn fin(&self) -> bool {
        unsafe { 
            (*self.buf.get_unchecked(13) & 1) == 1
        }
    }

    fn window(&self) -> u16 { 
        unsafe { 
            u16_from_buf_unchecked(self.buf, 14)
        }
    }

    fn checksum(&self) -> u16 {
        unsafe { 
            u16_from_buf_unchecked(self.buf, 16)
        }
    }

    fn urgent_pointer(&self) -> u16 {
        unsafe { 
            u16_from_buf_unchecked(self.buf, 18)
        }
    }

    fn options(&self) -> &'a [u8] { 
        let data_offset = unsafe { 
            *self.buf.get_unchecked(12) >> 4
        };
        let data_offset = usize::from(data_offset * 4);

        &self.buf[MIN_TCP_HEADER_LENGTH..data_offset]
    }

    fn data(&self) -> &'a [u8] {
        let data_offset = unsafe { 
            *self.buf.get_unchecked(12) >> 4
        };
        let data_offset = usize::from(data_offset * 4);

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

struct PsuedoHeader { 
    src_addr: Ipv4Addr, 
    dst_addr: Ipv4Addr, 
    protocol: Protocol,
    tcp_length: u16,
}

impl PsuedoHeader { 
    fn from_ip(ip: &Ipv4HeaderSlice) -> Self { 
        let tcp_length = ip.length() - (ip.header_length() as u16);

        Self {
            src_addr: ip.src_ip(), 
            dst_addr: ip.dst_ip(), 
            protocol: ip.protocol(), 
            tcp_length
        }
    }
}

// If index and index + 1 are outside of the buffers length 
// then this will lead to undetermined behavior
unsafe fn u16_to_buf_unchecked(buf: &mut [u8], index: usize, val: u16) { 
    unsafe { 
        *buf.get_unchecked_mut(index) = (val >> 8) as u8;
        *buf.get_unchecked_mut(index + 1) = (val & 0xFF) as u8;
    }
}

// If index..index + 3 are outside of the buffers length 
// then this will lead to undetermined behavior
unsafe fn u32_to_buf_unchecked(buf: &mut [u8], index: usize, val: u32)  { 
    for i in 0..4 { 
        let shift = 24 - (i * 8);
        unsafe {
            *buf.get_unchecked_mut(index + i) = ((val >> shift) & 0xFF) as u8;
        };
    }
}

struct TcpHeader<'a> { 
    src_port: u16, 
    dst_port: u16, 
    seq_number: u32, 
    ack_number: u32,
    cwr: bool, 
    ece: bool, 
    urg: bool, 
    ack: bool, 
    psh: bool,
    rst: bool, 
    syn: bool, 
    fin: bool, 
    window: u16, 
    psuedo_header: PsuedoHeader,
    urgent_pointer: u16, 
    options: &'a [u8],
    data: &'a [u8],
}

impl Debug for TcpHeader<'_> { 
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { 
        f.debug_struct("TcpHeaderSlice")
            .field("source port", &self.src_port)
            .field("destination port", &self.dst_port)
            .field("sequence number", &self.seq_number)
            .field("acknowledgment number", &self.ack_number)
            .field("flag (cwr)", &self.cwr)
            .field("flag (ece)", &self.ece)
            .field("flag (urg)", &self.urg)
            .field("flag (ack)", &self.ack)
            .field("flag (psh)", &self.psh)
            .field("flag (rst)", &self.rst)
            .field("flag (syn)", &self.syn)
            .field("flag (fin)", &self.fin)
            .field("window", &self.window)
            .field("urgent pointer", &self.urgent_pointer)
            .finish()
    }
}

impl TcpHeader<'_> {
    // FIXME: let us have this return a error
    // TODO: need to have this sudo header shit
    fn to_buf(&self, buf: &mut [u8]) { 
        let tcp_size = MIN_TCP_HEADER_LENGTH + self.options.len() + self.data.len();

        if buf.len() < (tcp_size) { 
            return;
        }

        let data_offset = (MIN_TCP_HEADER_LENGTH + self.options.len()) / 4;
        unsafe { 
            u16_to_buf_unchecked(buf, 0, self.src_port);

            u16_to_buf_unchecked(buf, 2, self.dst_port);

            u32_to_buf_unchecked(buf, 4, self.seq_number);
            u32_to_buf_unchecked(buf, 8, self.ack_number);

            *buf.get_unchecked_mut(12) = (data_offset << 4) as u8; 

            *buf.get_unchecked_mut(13) = 0;
            *buf.get_unchecked_mut(13) |= (self.cwr as u8) << 7;
            *buf.get_unchecked_mut(13) |= (self.ece as u8) << 6;
            *buf.get_unchecked_mut(13) |= (self.urg as u8) << 5;
            *buf.get_unchecked_mut(13) |= (self.ack as u8) << 4;
            *buf.get_unchecked_mut(13) |= (self.psh as u8) << 3;
            *buf.get_unchecked_mut(13) |= (self.rst as u8) << 2;
            *buf.get_unchecked_mut(13) |= (self.syn as u8) << 1;
            *buf.get_unchecked_mut(13) |= self.fin as u8;
            
            u16_to_buf_unchecked(buf, 14, self.window);
            
            // initialize the checksum to zero
            u16_to_buf_unchecked(buf, 16, 0);

            u16_to_buf_unchecked(buf, 18, self.urgent_pointer);
        }

        let mut cur_index = MIN_TCP_HEADER_LENGTH;

        for val in self.options.iter() { 
            unsafe { 
                *buf.get_unchecked_mut(cur_index) = *val;
                cur_index += 1;
            }
        }

        for val in self.data.iter() { 
            unsafe {
                *buf.get_unchecked_mut(cur_index) = *val; 
                cur_index += 1;
            }
        }

        let src_addr = self.psuedo_header.src_addr.to_bits();
        let dst_addr = self.psuedo_header.dst_addr.to_bits();
        
        // Required to calculate the checksum of a psuedo header
        let mut checksum = ones_complement_sum((src_addr >> 16) as u16, (src_addr & 0xFFFF) as u16);
        checksum = ones_complement_sum(checksum, (dst_addr >> 16) as u16);
        checksum = ones_complement_sum(checksum, (dst_addr & 0xFFFF) as u16);
        checksum = ones_complement_sum(checksum, self.psuedo_header.protocol.to_bits() as u16);
        checksum = ones_complement_sum(checksum, self.psuedo_header.tcp_length);


        for i in (0..cur_index - 1).step_by(2) { 
            let word = unsafe { 
                u16_from_buf_unchecked(buf, i)
            };
            checksum = ones_complement_sum(checksum, word);
        }

        // if there is a odd number of octets add the last octet
        // with 0 padding to the right
        if cur_index % 2 == 1 { 
             let word = unsafe { 
                 (*buf.get_unchecked_mut(cur_index - 1) as u16) << 8
             };
             checksum = ones_complement_sum(checksum, word);
        }

        checksum = !checksum;

        unsafe { 
            u16_to_buf_unchecked(buf, 16, checksum);
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
                        process_packet(&ip, &interface, &buf[usize::from(4 + ip.header_length())..byte_len]);
                    }
                    None => {
                        println!("\n\nIgnoring Ipv6 Packet");
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
