#![no_std]

use core::mem;

use network_types::{arp::ArpHdr, eth::EthHdr, icmp::IcmpHdr, ip::IpHdr, tcp::TcpHdr, udp::UdpHdr};

pub mod protocols;

pub const MAX_FIREWALL_RULES: u32 = 32;
pub const MAX_RULES_PORT: usize = 32;

#[repr(C)]
#[derive(Clone)]
pub struct RawFrame {
    pub header: EthHdr,
    pub payload: RawPacket,
}

impl RawFrame {
    pub const LEN: usize = mem::size_of::<RawFrame>();
}

#[repr(C)]
pub enum RawPacket {
    Ip(IpHdr, ProtoHdr),
    Arp(ArpHdr),
}

impl Clone for RawPacket {
    fn clone(&self) -> Self {
        match self {
            Self::Ip(ip_hdr, proto_hdr) => match ip_hdr {
                IpHdr::V4(ipv4_hdr) => Self::Ip(IpHdr::V4(*ipv4_hdr), *proto_hdr),
                IpHdr::V6(ipv6_hdr) => Self::Ip(IpHdr::V6(*ipv6_hdr), *proto_hdr),
            },
            Self::Arp(arp_hdr) => Self::Arp(*arp_hdr),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Icmp(IcmpHdr),
}
