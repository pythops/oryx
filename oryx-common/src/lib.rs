#![no_std]

use core::mem;

use network_types::{arp::ArpHdr, icmp::IcmpHdr, ip::IpHdr, tcp::TcpHdr, udp::UdpHdr};

pub mod ip;
pub mod protocols;

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
