pub mod icmp;
pub mod igmp;
pub mod ip;

use core::fmt::Display;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use ip::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};

use crate::packet::network::{icmp::IcmpPacket, ip::IpProto};

#[derive(Debug, Copy, Clone)]
pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

impl IpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        match self {
            IpPacket::V4(ip_packet) => match ip_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(20), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };

                    ip_packet.render(network_block, frame);
                    tcp_packet.render(transport_block, frame);
                }
                IpProto::Udp(udp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(8), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    udp_packet.render(transport_block, frame);
                }
                IpProto::Sctp(sctp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(8), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    sctp_packet.render(transport_block, frame);
                }
                IpProto::Icmp(IcmpPacket::V4(icmp_packet)) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(7), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    icmp_packet.render(transport_block, frame);
                }
                IpProto::Igmp(igmp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(7), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    igmp_packet.render(transport_block, frame);
                }
                _ => unreachable!(),
            },
            IpPacket::V6(ip_packet) => match ip_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(20), Constraint::Length(10)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };

                    ip_packet.render(network_block, frame);
                    tcp_packet.render(transport_block, frame);
                }
                IpProto::Udp(udp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(8), Constraint::Length(10)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    udp_packet.render(transport_block, frame);
                }
                IpProto::Sctp(sctp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(8), Constraint::Length(10)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    sctp_packet.render(transport_block, frame);
                }
                IpProto::Icmp(IcmpPacket::V6(icmp_packet)) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(7), Constraint::Length(10)])
                            .flex(ratatui::layout::Flex::SpaceAround)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    icmp_packet.render(transport_block, frame);
                }
                _ => unreachable!(),
            },
        }
    }
}

impl Display for IpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} TCP",
                        ipv4_packet.src_ip,
                        tcp_packet.src_port,
                        ipv4_packet.dst_ip,
                        tcp_packet.dst_port
                    )
                }
                IpProto::Udp(udp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} UDP",
                        ipv4_packet.src_ip,
                        udp_packet.src_port,
                        ipv4_packet.dst_ip,
                        udp_packet.dst_port
                    )
                }
                IpProto::Sctp(sctp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} SCTP",
                        ipv4_packet.src_ip,
                        sctp_packet.src_port,
                        ipv4_packet.dst_ip,
                        sctp_packet.dst_port
                    )
                }
                IpProto::Icmp(_) => {
                    write!(f, "{} {} ICMP", ipv4_packet.src_ip, ipv4_packet.dst_ip)
                }
                IpProto::Igmp(_) => {
                    write!(f, "{} {} IGMP", ipv4_packet.src_ip, ipv4_packet.dst_ip)
                }
            },
            IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} TCP",
                        ipv6_packet.src_ip,
                        tcp_packet.src_port,
                        ipv6_packet.dst_ip,
                        tcp_packet.dst_port
                    )
                }
                IpProto::Udp(udp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} UDP",
                        ipv6_packet.src_ip,
                        udp_packet.src_port,
                        ipv6_packet.dst_ip,
                        udp_packet.dst_port
                    )
                }
                IpProto::Sctp(sctp_packet) => {
                    write!(
                        f,
                        "{} {} {} {} SCTP",
                        ipv6_packet.src_ip,
                        sctp_packet.src_port,
                        ipv6_packet.dst_ip,
                        sctp_packet.dst_port
                    )
                }
                IpProto::Icmp(_) => {
                    write!(f, "{} {} ICMP", ipv6_packet.src_ip, ipv6_packet.dst_ip)
                }
                IpProto::Igmp(_) => {
                    unreachable!()
                }
            },
        }
    }
}
