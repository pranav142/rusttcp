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
    rx_buffer: VecDeque<u8>,
}

impl TcpConn {
    fn new() -> Self {
        Self {
            state: TcpState::Listen,
            rcv: RecvSeq::default(),
            snd: SendSeq::default(),
            rx_buffer: VecDeque::new(),
        }
    }

    // TODO: Need to generate a random ISN
    fn generate_isn(&self) -> u32 { 
        100000
    }

    // returns the number of bytes of the tcp response
    // right now we are returning the number of bytes of the TCP response
    fn on_packet(
        &mut self,
        ip: &Ipv4HeaderSlice<'_>,
        tcp: &TcpHeaderSlice<'_>,
    ) -> Option<TcpHeader> {
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
                    options: &Vec::new(),
                    data: &Vec::new(),
                };

                self.state = TcpState::SynRecieved;

                Some(tcp_response)
            }, 
            TcpState::SynRecieved => { 
                if !tcp.ack() { 
                    return None;
                }

                if tcp.ack_number() != self.snd.nxt { 
                    return None;
                }

                println!("\nEstablishing Connection");
                self.state = TcpState::Established;
                None  
            },
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

        let Some(tcp_response) = connection.on_packet(ip, tcp) else { 
            return
        };
        
        let ipv4_header = ip.reply(tcp_response.length());

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

