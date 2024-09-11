#![no_std]

use core::{
    fmt::Display,
    mem,
    net::{IpAddr, Ipv4Addr},
};

use arp::{ArpPacket, ArpType, MacAddr};
use ip::{IcmpPacket, IcmpType, IpPacket, ProtoHdr, TcpPacket, UdpPacket};
use network_types::{arp::ArpHdr, ip::IpHdr};

pub mod arp;
pub mod ip;

#[repr(C)]
pub enum RawPacket {
    Ip(IpHdr, ip::ProtoHdr),
    Arp(ArpHdr),
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<RawPacket>();
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum AppPacket {
    Ip(IpPacket),
    Arp(ArpPacket),
}

impl AppPacket {
    pub const LEN: usize = mem::size_of::<Self>();
}

impl Display for AppPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Arp(packet) => write!(f, "{}", packet),
            Self::Ip(packet) => write!(f, "{}", packet),
        }
    }
}

impl From<[u8; RawPacket::LEN]> for AppPacket {
    fn from(value: [u8; RawPacket::LEN]) -> Self {
        let raw_packet = value.as_ptr() as *const RawPacket;
        match unsafe { &*raw_packet } {
            RawPacket::Ip(packet, proto) => match packet {
                IpHdr::V4(ipv4_packet) => match proto {
                    ProtoHdr::Tcp(header) => {
                        let tcp_packet = TcpPacket {
                            src_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.src_addr))),
                            src_port: u16::from_be(header.source),
                            dst_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.dst_addr))),
                            dst_port: u16::from_be(header.dest),
                        };
                        AppPacket::Ip(IpPacket::Tcp(tcp_packet))
                    }
                    ProtoHdr::Udp(header) => {
                        let udp_packet = UdpPacket {
                            src_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.src_addr))),
                            src_port: u16::from_be(header.source),
                            dst_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.dst_addr))),
                            dst_port: u16::from_be(header.dest),
                        };
                        Self::Ip(IpPacket::Udp(udp_packet))
                    }
                    ProtoHdr::Icmp(header) => {
                        let icmp_type = match header.type_ {
                            0 => IcmpType::EchoRequest,
                            1 => IcmpType::EchoReply,
                            _ => IcmpType::DestinationUnreachable,
                        };

                        let icmp_packet = IcmpPacket {
                            src_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.src_addr))),
                            dst_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_packet.dst_addr))),
                            icmp_type,
                        };
                        Self::Ip(IpPacket::Icmp(icmp_packet))
                    }
                },
                IpHdr::V6(ipv6_packet) => match proto {
                    ProtoHdr::Tcp(header) => {
                        let tcp_packet = TcpPacket {
                            src_ip: IpAddr::V6(ipv6_packet.src_addr()),
                            src_port: u16::from_be(header.source),
                            dst_ip: IpAddr::V6(ipv6_packet.dst_addr()),
                            dst_port: u16::from_be(header.dest),
                        };
                        Self::Ip(IpPacket::Tcp(tcp_packet))
                    }
                    ProtoHdr::Udp(header) => {
                        let udp_packet = UdpPacket {
                            src_ip: IpAddr::V6(ipv6_packet.src_addr()),
                            src_port: u16::from_be(header.source),
                            dst_ip: IpAddr::V6(ipv6_packet.dst_addr()),
                            dst_port: u16::from_be(header.dest),
                        };
                        Self::Ip(IpPacket::Udp(udp_packet))
                    }
                    ProtoHdr::Icmp(header) => {
                        let icmp_type = match header.type_ {
                            0 => IcmpType::EchoRequest,
                            1 => IcmpType::EchoReply,
                            _ => IcmpType::DestinationUnreachable,
                        };

                        let icmp_packet = IcmpPacket {
                            src_ip: IpAddr::V6(ipv6_packet.src_addr()),
                            dst_ip: IpAddr::V6(ipv6_packet.dst_addr()),
                            icmp_type,
                        };
                        Self::Ip(IpPacket::Icmp(icmp_packet))
                    }
                },
            },
            RawPacket::Arp(packet) => {
                let arp_type = match u16::from_be(packet.oper) {
                    1 => ArpType::Request,
                    2 => ArpType::Reply,
                    _ => unreachable!(),
                };

                Self::Arp(ArpPacket {
                    arp_type,
                    src_mac: MacAddr(packet.sha),
                    dst_mac: MacAddr(packet.tha),
                })
            }
        }
    }
}
