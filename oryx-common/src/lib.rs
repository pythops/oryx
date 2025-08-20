#![no_std]
#![feature(trivial_bounds)]

use core::mem;

use network_types::{
    arp::ArpHdr, eth::EthHdr, icmp::IcmpHdr, ip::IpHdr, sctp::SctpHdr, tcp::TcpHdr, udp::UdpHdr,
};

pub mod protocols;

pub const MAX_FIREWALL_RULES: u32 = 32;
pub const MAX_RULES_PORT: usize = 32;

#[derive(Clone)]
#[repr(C)]
pub struct RawData {
    pub frame: RawFrame,
    pub pid: Option<u32>,
}

impl RawData {
    pub const LEN: usize = mem::size_of::<RawData>();
}

impl From<[u8; RawData::LEN]> for RawData {
    fn from(value: [u8; RawData::LEN]) -> Self {
        unsafe { core::mem::transmute::<[u8; RawData::LEN], Self>(value) }
    }
}

#[derive(Clone)]
#[repr(C)]
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

#[derive(Copy, Clone)]
#[repr(C)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Sctp(SctpHdr),
    Icmp(IcmpHdr),
}
