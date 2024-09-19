#![no_std]

use core::{fmt::Display, mem, net::Ipv4Addr};

use arp::{ArpPacket, ArpType, MacAddr};
use ip::{IcmpPacket, IcmpType, IpPacket, IpProto, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use network_types::{arp::ArpHdr, icmp::IcmpHdr, ip::IpHdr, tcp::TcpHdr, udp::UdpHdr};

pub mod arp;
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
                IpHdr::V4(ipv4_packet) => {
                    let src_ip = Ipv4Addr::from(u32::from_be(ipv4_packet.src_addr));
                    let dst_ip = Ipv4Addr::from(u32::from_be(ipv4_packet.dst_addr));

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be(tcp_header.source),
                            dst_port: u16::from_be(tcp_header.dest),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be(udp_header.source),
                            dst_port: u16::from_be(udp_header.dest),
                        }),
                        ProtoHdr::Icmp(header) => {
                            let icmp_type = match header.type_ {
                                0 => IcmpType::EchoRequest,
                                1 => IcmpType::EchoReply,
                                _ => IcmpType::DestinationUnreachable,
                            };
                            IpProto::Icmp(IcmpPacket { icmp_type })
                        }
                    };

                    AppPacket::Ip(IpPacket::V4(Ipv4Packet {
                        src_ip,
                        dst_ip,
                        proto,
                    }))
                }
                IpHdr::V6(ipv6_packet) => {
                    let src_ip = ipv6_packet.src_addr();
                    let dst_ip = ipv6_packet.dst_addr();

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be(tcp_header.source),
                            dst_port: u16::from_be(tcp_header.dest),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be(udp_header.source),
                            dst_port: u16::from_be(udp_header.dest),
                        }),
                        ProtoHdr::Icmp(header) => {
                            let icmp_type = match header.type_ {
                                0 => IcmpType::EchoRequest,
                                1 => IcmpType::EchoReply,
                                _ => IcmpType::DestinationUnreachable,
                            };
                            IpProto::Icmp(IcmpPacket { icmp_type })
                        }
                    };

                    AppPacket::Ip(IpPacket::V6(Ipv6Packet {
                        src_ip,
                        dst_ip,
                        proto,
                    }))
                }
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
