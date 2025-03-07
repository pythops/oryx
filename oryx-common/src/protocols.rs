use core::{fmt::Display, str::FromStr};

#[derive(Debug, Copy, Clone)]
#[repr(C, u8)]
pub enum Protocol {
    Transport(TransportProtocol) = 0,
    Network(NetworkProtocol) = 1,
    Link(LinkProtocol) = 2,
}

#[derive(Debug, PartialEq)]
pub struct ParseProtocolError;

// Transport Protocols

pub const NB_TRANSPORT_PROTOCOL: u16 = 2;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum TransportProtocol {
    TCP = 0,
    UDP = 1,
}

impl TransportProtocol {
    pub fn all() -> [TransportProtocol; 2] {
        [TransportProtocol::TCP, TransportProtocol::UDP]
    }
}

impl Display for TransportProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportProtocol::TCP => write!(f, "Tcp"),
            TransportProtocol::UDP => write!(f, "Udp"),
        }
    }
}

impl FromStr for TransportProtocol {
    type Err = ParseProtocolError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Udp" | "udp" => Ok(Self::UDP),
            "Tcp" | "tcp" => Ok(Self::TCP),
            _ => Err(ParseProtocolError),
        }
    }
}

// Network Protocols

pub const NB_NETWORK_PROTOCOL: u16 = 3;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum NetworkProtocol {
    Ipv4 = 0,
    Ipv6 = 1,
    Icmp = 2,
}

impl NetworkProtocol {
    pub fn all() -> [NetworkProtocol; 3] {
        [
            NetworkProtocol::Ipv4,
            NetworkProtocol::Ipv6,
            NetworkProtocol::Icmp,
        ]
    }
}

impl Display for NetworkProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NetworkProtocol::Ipv4 => write!(f, "Ipv4"),
            NetworkProtocol::Ipv6 => write!(f, "Ipv6"),
            NetworkProtocol::Icmp => write!(f, "Icmp"),
        }
    }
}

impl FromStr for NetworkProtocol {
    type Err = ParseProtocolError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ipv4" | "ipv4" => Ok(Self::Ipv4),
            "Ipv6" | "ipv6" => Ok(Self::Ipv6),
            "Icmp" | "icmp" => Ok(Self::Icmp),
            _ => Err(ParseProtocolError),
        }
    }
}

// Link Protocols

pub const NB_LINK_PROTOCOL: u16 = 1;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum LinkProtocol {
    Arp = 0,
}

impl LinkProtocol {
    pub fn all() -> [LinkProtocol; 1] {
        [LinkProtocol::Arp]
    }
}

impl Display for LinkProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Arp")
    }
}

impl FromStr for LinkProtocol {
    type Err = ParseProtocolError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Arp" | "arp" => Ok(Self::Arp),
            _ => Err(ParseProtocolError),
        }
    }
}
