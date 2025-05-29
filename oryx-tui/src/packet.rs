pub mod direction;
pub mod eth_frame;
pub mod link;
pub mod network;
pub mod transport;

use std::{fmt::Display, mem, net::Ipv4Addr};

use direction::TrafficDirection;
use link::{ArpPacket, ArpType, MacAddr};
use network::{IcmpPacket, IcmpType, IpPacket, IpProto, Ipv4Packet, Ipv6Packet};
use network_types::{eth::EthHdr, ip::IpHdr};
use oryx_common::{ProtoHdr, RawFrame, RawPacket};
use transport::{TcpPacket, UdpPacket};

#[derive(Debug, Copy, Clone)]
pub struct AppPacket {
    pub frame: EthFrame,
    pub direction: TrafficDirection,
    pub pid: Option<u32>,
}

#[derive(Debug, Copy, Clone)]
pub struct EthFrame {
    pub header: EthHdr,
    pub payload: NetworkPacket,
}

impl AppPacket {
    pub const LEN: usize = mem::size_of::<Self>();
}

#[derive(Debug, Copy, Clone)]
pub enum NetworkPacket {
    Ip(IpPacket),
    Arp(ArpPacket),
}

impl Display for NetworkPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Arp(packet) => write!(f, "{packet}"),
            Self::Ip(packet) => write!(f, "{packet}"),
        }
    }
}

impl From<RawFrame> for EthFrame {
    fn from(value: RawFrame) -> Self {
        match value.payload {
            RawPacket::Ip(packet, proto) => match packet {
                IpHdr::V4(ipv4_packet) => {
                    let src_ip = Ipv4Addr::from(u32::from_be(ipv4_packet.src_addr));
                    let dst_ip = Ipv4Addr::from(u32::from_be(ipv4_packet.dst_addr));

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be(tcp_header.source),
                            dst_port: u16::from_be(tcp_header.dest),
                            seq: u32::from_be(tcp_header.seq),
                            ack_seq: u32::from_be(tcp_header.ack_seq),
                            data_offset: tcp_header.doff(),
                            cwr: tcp_header.cwr(),
                            ece: tcp_header.ece(),
                            urg: tcp_header.urg(),
                            ack: tcp_header.ack(),
                            psh: tcp_header.psh(),
                            rst: tcp_header.rst(),
                            syn: tcp_header.syn(),
                            fin: tcp_header.fin(),
                            window: u16::from_be(tcp_header.window),
                            checksum: u16::from_be(tcp_header.check),
                            urg_ptr: u16::from_be(tcp_header.urg_ptr),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be(udp_header.source),
                            dst_port: u16::from_be(udp_header.dest),
                            length: u16::from_be(udp_header.len),
                            checksum: u16::from_be(udp_header.check),
                        }),
                        ProtoHdr::Icmp(icmp_header) => {
                            let icmp_type = match u8::from_be(icmp_header.type_) {
                                0 => IcmpType::EchoReply,
                                3 => IcmpType::DestinationUnreachable,
                                5 => IcmpType::RedirectMessage,
                                8 => IcmpType::EchoRequest,
                                9 => IcmpType::RouterAdvertisement,
                                10 => IcmpType::RouterSolicitation,
                                11 => IcmpType::TimeExceeded,
                                12 => IcmpType::BadIPheader,
                                13 => IcmpType::Timestamp,
                                14 => IcmpType::TimestampReply,
                                42 => IcmpType::ExtendedEchoRequest,
                                43 => IcmpType::ExtendedEchoReply,
                                _ => IcmpType::Deprecated,
                            };
                            IpProto::Icmp(IcmpPacket {
                                icmp_type,
                                code: u8::from_be(icmp_header.code),
                                checksum: u16::from_be(icmp_header.checksum),
                            })
                        }
                    };

                    EthFrame {
                        header: value.header,
                        payload: NetworkPacket::Ip(IpPacket::V4(Ipv4Packet {
                            src_ip,
                            dst_ip,
                            ihl: u8::from_be(ipv4_packet.ihl()),
                            tos: u8::from_be(ipv4_packet.tos),
                            total_length: u16::from_be(ipv4_packet.tot_len),
                            id: u16::from_be(ipv4_packet.id),
                            fragment_offset: u16::from_be(ipv4_packet.frag_off),
                            ttl: u8::from_be(ipv4_packet.ttl),
                            checksum: u16::from_be(ipv4_packet.check),
                            proto,
                        })),
                    }
                }
                IpHdr::V6(ipv6_packet) => {
                    let src_ip = ipv6_packet.src_addr();
                    let dst_ip = ipv6_packet.dst_addr();

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be(tcp_header.source),
                            dst_port: u16::from_be(tcp_header.dest),
                            seq: u32::from_be(tcp_header.seq),
                            ack_seq: u32::from_be(tcp_header.ack_seq),
                            data_offset: tcp_header.doff(),
                            cwr: tcp_header.cwr(),
                            ece: tcp_header.ece(),
                            urg: tcp_header.urg(),
                            ack: tcp_header.ack(),
                            psh: tcp_header.psh(),
                            rst: tcp_header.rst(),
                            syn: tcp_header.syn(),
                            fin: tcp_header.fin(),
                            window: u16::from_be(tcp_header.window),
                            checksum: u16::from_be(tcp_header.check),
                            urg_ptr: u16::from_be(tcp_header.urg_ptr),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be(udp_header.source),
                            dst_port: u16::from_be(udp_header.dest),
                            length: u16::from_be(udp_header.len),
                            checksum: u16::from_be(udp_header.check),
                        }),
                        ProtoHdr::Icmp(icmp_header) => {
                            let icmp_type = match u8::from_be(icmp_header.type_) {
                                0 => IcmpType::EchoReply,
                                3 => IcmpType::DestinationUnreachable,
                                5 => IcmpType::RedirectMessage,
                                8 => IcmpType::EchoRequest,
                                9 => IcmpType::RouterAdvertisement,
                                10 => IcmpType::RouterSolicitation,
                                11 => IcmpType::TimeExceeded,
                                12 => IcmpType::BadIPheader,
                                13 => IcmpType::Timestamp,
                                14 => IcmpType::TimestampReply,
                                42 => IcmpType::ExtendedEchoRequest,
                                43 => IcmpType::ExtendedEchoReply,
                                _ => IcmpType::Deprecated,
                            };
                            IpProto::Icmp(IcmpPacket {
                                icmp_type,
                                code: u8::from_be(icmp_header.code),
                                checksum: u16::from_be(icmp_header.checksum),
                            })
                        }
                    };

                    EthFrame {
                        header: value.header,
                        payload: NetworkPacket::Ip(IpPacket::V6(Ipv6Packet {
                            traffic_class: ipv6_packet.priority(),
                            flow_label: ipv6_packet.flow_label,
                            payload_length: u16::from_be(ipv6_packet.payload_len),
                            hop_limit: u8::from_be(ipv6_packet.hop_limit),
                            src_ip,
                            dst_ip,
                            proto,
                        })),
                    }
                }
            },
            RawPacket::Arp(packet) => {
                let arp_type = match u16::from_be(packet.oper) {
                    1 => ArpType::Request,
                    2 => ArpType::Reply,
                    _ => unreachable!(),
                };

                EthFrame {
                    header: value.header,
                    payload: NetworkPacket::Arp(ArpPacket {
                        htype: packet.ptype,
                        ptype: packet.ptype,
                        hlen: u8::from_be(packet.hlen),
                        plen: u8::from_be(packet.plen),
                        arp_type,
                        src_mac: MacAddr(packet.sha),
                        src_ip: Ipv4Addr::from(packet.spa),
                        dst_mac: MacAddr(packet.tha),
                        dst_ip: Ipv4Addr::from(packet.tpa),
                    }),
                }
            }
        }
    }
}
