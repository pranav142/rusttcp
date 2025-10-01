#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unsupported,
}

impl Protocol {
    pub fn from_bits(bits: u8) -> Self {
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

    pub fn to_bits(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unsupported => 0,
        }
    }
}
