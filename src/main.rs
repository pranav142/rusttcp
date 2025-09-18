use std::{net::Ipv4Addr, usize, vec};

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
    pub fn from_buf(buf: &[u8]) -> Option<Self> {
        let os_flags = TunFlags { 
            flags: u16_from_u8(buf, 0),
            proto: u16_from_u8(buf, 2),
        };
        
        let version = (buf[4] & 0xF0) >> 4;

        if version != 4 { 
            return None;
        }

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

        let checksum = u16_from_u8(buf, 14);

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
