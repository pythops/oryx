#![no_std]

use core::mem::{self, transmute};

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

pub fn to_u128(x: [u16; 8]) -> u128 {
    //     (u128::from(x[0]) << 96)
    //         | (u128::from(x[1]) << 64)
    //         | (u128::from(x[2]) << 32)
    //         | u128::from(x[3])
    // }

    let addr16 = x.map(|x| x.to_be());
    u128::from_be_bytes(unsafe { transmute::<_, [u8; 16]>(addr16) })
}
