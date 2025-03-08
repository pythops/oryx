use strum::{AsRefStr, Display, EnumString};

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

#[derive(Debug, Copy, Clone, PartialEq, AsRefStr, Display, EnumString)]
#[repr(C)]
pub enum TransportProtocol {
    #[strum(ascii_case_insensitive)]
    TCP = 0,

    #[strum(ascii_case_insensitive)]
    UDP = 1,
}

impl TransportProtocol {
    pub fn all() -> [TransportProtocol; 2] {
        [TransportProtocol::TCP, TransportProtocol::UDP]
    }
}

// Network Protocols

pub const NB_NETWORK_PROTOCOL: u16 = 3;

#[derive(Debug, Copy, Clone, PartialEq, AsRefStr, Display, EnumString)]
#[repr(C)]
pub enum NetworkProtocol {
    #[strum(ascii_case_insensitive)]
    Ipv4 = 0,

    #[strum(ascii_case_insensitive)]
    Ipv6 = 1,

    #[strum(ascii_case_insensitive)]
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

// Link Protocols

pub const NB_LINK_PROTOCOL: u16 = 1;

#[derive(Debug, Copy, Clone, PartialEq, AsRefStr, Display, EnumString)]
#[repr(C)]
pub enum LinkProtocol {
    #[strum(ascii_case_insensitive)]
    Arp = 0,
}

impl LinkProtocol {
    pub fn all() -> [LinkProtocol; 1] {
        [LinkProtocol::Arp]
    }
}
