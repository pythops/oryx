#![no_std]

use core::mem;

use network_types::{arp::ArpHdr, icmp::IcmpHdr, ip::IpHdr, tcp::TcpHdr, udp::UdpHdr};

pub mod protocols;

pub const MAX_FIREWALL_RULES: u32 = 32;
pub const MAX_RULES_PORT: usize = 32;

#[repr(C)]
pub enum RawPacket {
    Ip(IpHdr, ProtoHdr),
    Arp(ArpHdr),
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Icmp(IcmpHdr),
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<RawPacket>();
}
