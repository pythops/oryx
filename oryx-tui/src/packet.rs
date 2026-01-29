pub mod direction;
pub mod eth_frame;
pub mod link;
pub mod network;
pub mod transport;

use std::{fmt::Display, mem, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use direction::TrafficDirection;
use link::{ArpPacket, ArpType, MacAddr};
use network::{IpPacket, icmp::IcmpPacket, icmp::icmpv4, icmp::icmpv6, ip::IpProto};
use network_types::{eth::EthHdr, icmp::Icmp, ip::IpHdr};
use oryx_common::{IGMPv3Hdr, IgmpHdr, ProtoHdr, RawFrame, RawPacket};
use transport::{SctpPacket, TcpPacket, UdpPacket};

use crate::packet::network::{
    icmp::{icmpv4::Icmpv4Packet, icmpv6::Icmpv6Packet},
    igmp::{
        IgmpPacket, IgmpType,
        igmpv1::IGMPv1Packet,
        igmpv2::IGMPv2Packet,
        igmpv3::{IGMPv3MembershipQueryPacket, IGMPv3MembershipReportPacket, IGMPv3Packet},
    },
    ip::{ipv4::Ipv4Packet, ipv6::Ipv6Packet},
};

#[derive(Debug, Copy, Clone)]
pub struct AppPacket {
    pub frame: EthFrame,
    pub direction: TrafficDirection,
    pub pid: Option<u32>,
    pub timestamp: DateTime<Utc>,
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
                    let src_ip = ipv4_packet.src_addr();
                    let dst_ip = ipv4_packet.dst_addr();

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be_bytes(tcp_header.source),
                            dst_port: u16::from_be_bytes(tcp_header.dest),
                            seq: u32::from_be_bytes(tcp_header.seq),
                            ack_seq: u32::from_be_bytes(tcp_header.ack_seq),
                            data_offset: tcp_header.doff(),
                            cwr: tcp_header.cwr(),
                            ece: tcp_header.ece(),
                            urg: tcp_header.urg(),
                            ack: tcp_header.ack(),
                            psh: tcp_header.psh(),
                            rst: tcp_header.rst(),
                            syn: tcp_header.syn(),
                            fin: tcp_header.fin(),
                            window: u16::from_be_bytes(tcp_header.window),
                            checksum: u16::from_be_bytes(tcp_header.check),
                            urg_ptr: u16::from_be_bytes(tcp_header.urg_ptr),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be_bytes(udp_header.src),
                            dst_port: u16::from_be_bytes(udp_header.dst),
                            length: u16::from_be_bytes(udp_header.len),
                            checksum: u16::from_be_bytes(udp_header.check),
                        }),
                        ProtoHdr::Sctp(sctp_header) => IpProto::Sctp(SctpPacket {
                            src_port: u16::from_be_bytes(sctp_header.src),
                            dst_port: u16::from_be_bytes(sctp_header.dst),
                            verification_tag: u32::from_be_bytes(sctp_header.verification_tag),
                            checksum: u32::from_be_bytes(sctp_header.checksum),
                        }),
                        ProtoHdr::Icmp(Icmp::V4(icmp_header)) => {
                            IpProto::Icmp(IcmpPacket::V4(Icmpv4Packet {
                                icmp_type: icmpv4::IcmpType::from(u8::from_be(icmp_header.type_)),
                                code: u8::from_be(icmp_header.code),
                                checksum: u16::from_be_bytes(icmp_header.check),
                            }))
                        }
                        ProtoHdr::Igmp(igmp_header) => match igmp_header {
                            IgmpHdr::V1(igmpv1_hdr) => {
                                let igmp_type =
                                    IgmpType::try_from(igmpv1_hdr.type_() | 1 << 1).unwrap();
                                IpProto::Igmp(IgmpPacket::V1(IGMPv1Packet {
                                    igmp_type,
                                    checksum: igmpv1_hdr.checksum(),
                                    group_address: Ipv4Addr::from_bits(igmpv1_hdr.group_address()),
                                }))
                            }
                            IgmpHdr::V2(igmpv2_hdr) => {
                                let igmp_type =
                                    IgmpType::try_from(igmpv2_hdr.message_type).unwrap();
                                IpProto::Igmp(IgmpPacket::V2(IGMPv2Packet {
                                    igmp_type,
                                    max_response_time: igmpv2_hdr.max_response_time,
                                    checksum: igmpv2_hdr.checksum(),
                                    group_address: Ipv4Addr::from_bits(igmpv2_hdr.group_address()),
                                }))
                            }
                            IgmpHdr::V3(igmpv3_hdr) => match igmpv3_hdr {
                                IGMPv3Hdr::Query(query) => IpProto::Igmp(IgmpPacket::V3(
                                    IGMPv3Packet::Query(IGMPv3MembershipQueryPacket {
                                        max_response_code: query.max_response_time,
                                        checksum: query.checksum(),
                                        group_address: Ipv4Addr::from_bits(query.group_address()),
                                        s: query.s(),
                                        qrv: query.qrv(),
                                        qqic: query.qqic,
                                        nb_source_addr: query.nb_sources() as u16,
                                    }),
                                )),
                                IGMPv3Hdr::Report(report) => IpProto::Igmp(IgmpPacket::V3(
                                    IGMPv3Packet::Report(IGMPv3MembershipReportPacket {
                                        checksum: report.checksum(),
                                        nb_group_records: report.nb_group_records(),
                                    }),
                                )),
                            },
                        },
                        _ => unreachable!(),
                    };

                    EthFrame {
                        header: value.header,
                        payload: NetworkPacket::Ip(IpPacket::V4(Ipv4Packet {
                            src_ip,
                            dst_ip,
                            ihl: u8::from_be(ipv4_packet.ihl()),
                            tos: u8::from_be(ipv4_packet.tos),
                            total_length: u16::from_be_bytes(ipv4_packet.tot_len),
                            id: u16::from_be_bytes(ipv4_packet.id),
                            fragment_offset: ipv4_packet.frag_offset(),
                            ttl: u8::from_be(ipv4_packet.ttl),
                            checksum: u16::from_be_bytes(ipv4_packet.check),
                            proto,
                        })),
                    }
                }
                IpHdr::V6(ipv6_packet) => {
                    let src_ip = ipv6_packet.src_addr();
                    let dst_ip = ipv6_packet.dst_addr();

                    let proto = match proto {
                        ProtoHdr::Tcp(tcp_header) => IpProto::Tcp(TcpPacket {
                            src_port: u16::from_be_bytes(tcp_header.source),
                            dst_port: u16::from_be_bytes(tcp_header.dest),
                            seq: u32::from_be_bytes(tcp_header.seq),
                            ack_seq: u32::from_be_bytes(tcp_header.ack_seq),
                            data_offset: tcp_header.doff(),
                            cwr: tcp_header.cwr(),
                            ece: tcp_header.ece(),
                            urg: tcp_header.urg(),
                            ack: tcp_header.ack(),
                            psh: tcp_header.psh(),
                            rst: tcp_header.rst(),
                            syn: tcp_header.syn(),
                            fin: tcp_header.fin(),
                            window: u16::from_be_bytes(tcp_header.window),
                            checksum: u16::from_be_bytes(tcp_header.check),
                            urg_ptr: u16::from_be_bytes(tcp_header.urg_ptr),
                        }),
                        ProtoHdr::Udp(udp_header) => IpProto::Udp(UdpPacket {
                            src_port: u16::from_be_bytes(udp_header.src),
                            dst_port: u16::from_be_bytes(udp_header.dst),
                            length: u16::from_be_bytes(udp_header.len),
                            checksum: u16::from_be_bytes(udp_header.check),
                        }),
                        ProtoHdr::Sctp(sctp_header) => IpProto::Sctp(SctpPacket {
                            src_port: u16::from_be_bytes(sctp_header.src),
                            dst_port: u16::from_be_bytes(sctp_header.dst),
                            verification_tag: u32::from_be_bytes(sctp_header.verification_tag),
                            checksum: u32::from_be_bytes(sctp_header.checksum),
                        }),
                        ProtoHdr::Icmp(Icmp::V6(icmp_header)) => {
                            IpProto::Icmp(IcmpPacket::V6(Icmpv6Packet {
                                icmp_type: icmpv6::IcmpType::from(u8::from_be(icmp_header.type_)),
                                code: u8::from_be(icmp_header.code),
                                checksum: u16::from_be_bytes(icmp_header.check),
                            }))
                        }
                        _ => unreachable!(),
                    };

                    EthFrame {
                        header: value.header,
                        payload: NetworkPacket::Ip(IpPacket::V6(Ipv6Packet {
                            ds: ipv6_packet.dscp(),
                            ecn: ipv6_packet.ecn(),
                            flow_label: ipv6_packet.flow_label(),
                            payload_length: u16::from_be_bytes(ipv6_packet.payload_len),
                            hop_limit: u8::from_be(ipv6_packet.hop_limit),
                            src_ip,
                            dst_ip,
                            proto,
                        })),
                    }
                }
            },
            RawPacket::Arp(packet) => {
                let arp_type = match u16::from_be_bytes(packet.oper) {
                    1 => ArpType::Request,
                    2 => ArpType::Reply,
                    _ => unreachable!(),
                };

                EthFrame {
                    header: value.header,
                    payload: NetworkPacket::Arp(ArpPacket {
                        htype: u16::from_be_bytes(packet.htype),
                        ptype: u16::from_be_bytes(packet.ptype),
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
