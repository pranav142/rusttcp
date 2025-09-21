use std::{net::Ipv4Addr, u16, usize, vec};

use tun_tap::{Iface, Mode::Tun};

#[derive(Debug)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl Protocol {
    pub(crate) fn from_bits(bits: u8) -> Self {
        if bits == 1 {
            return Self::Icmp;
        }

        if bits == 6 {
            return Self::Tcp;
        }
        
        if bits == 17 {
            return Self::Udp;
        }

        Self::Unknown
    }
}

#[derive(Debug)]
struct TunFlags {
    flags: u16,
    proto: u16,
}

#[derive(Debug)]
struct IP {
    os_flags: TunFlags,
    version: u8,
    ihl: u8,
    tos: u8,
    length: u16,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

fn u16_from_u8(buf: &[u8], index: usize) -> u16 {
    ((buf[index] as u16) << 8) | buf[index + 1] as u16
}

fn u32_from_u8(buf: &[u8], index: usize) -> u32 {
    let mut total = 0;
    for offset in 0..4 {
        total <<= 8;
        total |= buf[index + offset] as u32;

    }
    total
}

impl IP {
    // TODO: Clean up magic numbers
    pub fn from_buf(buf: &[u8]) -> Option<Self> {       
        let version = (buf[4] & 0xF0) >> 4;
        
        // TODO: Only support version 4 right now
        if version != 4 { 
            return None;
        }

        let checksum = u16_from_u8(buf, 14);
        
        if compute_ip_checksum(buf) != checksum { 
            return None;
        }

        let os_flags = TunFlags { 
            flags: u16_from_u8(buf, 0),
            proto: u16_from_u8(buf, 2),
        };

        let ihl = buf[4] & 0xF;

        let tos = buf[5];
        let length = u16_from_u8(buf, 6);
        let identification = u16_from_u8(buf, 8);

        let parts = u16_from_u8(buf, 10);
        let fragment_offset = parts & 0x1FFF;

        let ip_flags = (parts & 0xD000) >> 13;
        let dont_fragment = ((ip_flags & 2) >> 1) == 1;
        let more_fragments = (ip_flags & 1) == 1;

        let ttl = buf[12];
        let protocol = Protocol::from_bits(buf[13]);

        let src_ip = Ipv4Addr::from_bits(u32_from_u8(buf, 16));
        let dst_ip = Ipv4Addr::from_bits(u32_from_u8(buf, 20));

        Some(IP { 
            os_flags,
            version,
            ihl,
            tos,
            length,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip
        })
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

pub fn compute_ip_checksum(buf: &[u8]) -> u16 { 
    let mut total = 0;
    let header_size_bytes = (buf[4] & 0xF) * 4;

    // Offset by 4 so we do not count the OS flags 
    // as part of the checksum
    let offset = 4;
    let end_index = header_size_bytes + offset;

    for i in (offset..end_index).step_by(2) {
        // skip the checksum bytes in the header
        if i == 14 {
            continue;
        }

        let header_word = u16_from_u8(buf, i.into());
        total = ones_complement_sum(total, header_word);
    }

    !total
}

// TODO: 
// Be able to parse ICMP request
// BE able to respond ot ICMP echo request with echo reply
const ECHO_MESSAGE: u8 = 8;

#[derive(Debug)]
struct Echo {
    echo_type: u8,
    code: u8,
    checksum: u16,
    identifier: u16, 
    sequence_number: u16,
}

#[derive(Debug)]
enum ICMP {
    Echo(Echo),
    EchoReply(Echo),
}

fn compute_echo_checksum(buf: &[u8]) -> u16 {
    let sum = ones_complement_sum(u16_from_u8(buf, 24), u16_from_u8(buf, 28));
    ones_complement_sum(sum, u16_from_u8(buf, 30))
}

impl ICMP { 
    fn from_buf(buf: &[u8]) -> Option<Self>{
        let icmp_type = buf[24];

        match icmp_type {
            0 | 8 => {
                let echo = Echo {
                    echo_type: icmp_type,
                    code: buf[25],
                    checksum: u16_from_u8(buf, 26),
                    identifier: u16_from_u8(buf, 28),
                    sequence_number: u16_from_u8(buf, 30),
                };


                if icmp_type == 8 {
                    return Some(Self::Echo(echo))
                }

                Some(Self::EchoReply(echo))
            },
            _ => {
                println!("Cannot deserialize unsupported or invalid icmp type: {icmp_type}");
                None
            }
        }
    }
}


fn process_ip(ip: &IP, interface: &Iface, buf: &mut [u8]) {
    match ip.protocol {
        Protocol::Icmp => {
            let icmp_type = buf[24];

            println!("\nrecieved icmp:\n {:?}", ICMP::from_buf(buf));

            if icmp_type != ECHO_MESSAGE { 
                return;
            }

            let src_ip = ip.src_ip.to_bits();
            let dst_ip = ip.dst_ip.to_bits();

            // this is sus that we do this manually
            for i in 0..4 {
                let shift = i * 8;
                let src_byte = (src_ip & (0xFF << shift)) >> shift;
                buf[23 - i] = src_byte as u8;
                let dst_byte = (dst_ip & (0xFF << shift)) >> shift;
                buf[19 - i] = dst_byte as u8;
            }

            let checksum = compute_ip_checksum(buf);
            buf[14] = ((checksum & 0xFF00) >> 8) as u8;
            buf[15] = (checksum & 0xFF) as u8;

            buf[24] = 0;


            // TODO: need to properly recompute the check sum
            let mut total = 0;
            let offset = 24;
            let icmp_header_length: u16 = 8;
            let end_index = icmp_header_length + offset;

            for i in (offset..end_index).step_by(2) {
                if i == 26 {
                    continue;
                }

                total = ones_complement_sum(total, u16_from_u8(buf, i.into()))
            }

            let mut data_start_index = end_index;
            let data_length = ip.length - (ip.ihl as u16 * 4) - icmp_header_length;

            let end_index = data_start_index + data_length;

            if data_length % 2 == 1 { 
                let zero_pad = (buf[data_start_index as usize] as u16) << 8;
                total = ones_complement_sum(total, zero_pad);
                data_start_index += 1;
            }
            
            for i in (data_start_index..end_index).step_by(2) {
                total = ones_complement_sum(total, u16_from_u8(buf, i.into()));
            }

            total = !total;

            buf[26] = ((total & 0xFF00) >> 8) as u8;
            buf[27] = (total & 0xFF) as u8;

            println!("\nconstructed icmp:\n {:?}", ICMP::from_buf(buf));

            let new_ip = IP::from_buf(buf);
            println!("\nnew ip:\n {:?}", new_ip);

            let result = interface.send(buf);
            match result {
                Ok(status) => {
                    println!("Succesfully sent ICMP echo reply: {}", status);
                },
                Err(error) => {
                    println!("Error sending ICMP echo reply: {}", error);
                }
            }

        },
        _ => {
            println!("Protocol not supported");
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
                let ip_opt = IP::from_buf(&buf);
                match ip_opt { 
                    Some(ip) => {
                        println!("Successfully recieved {} bytes, message ID: {}", byte_len, msg_id);
                        println!("IP: {:?}", ip);
                        process_ip(&ip, &interface, &mut buf);
                    }
                    None => {
                        println!("Ignoring Packet");
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
