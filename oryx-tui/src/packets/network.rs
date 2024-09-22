use core::fmt::Display;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
    Frame,
};

use core::net::{Ipv4Addr, Ipv6Addr};

use super::transport::{TcpPacket, UdpPacket};

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
                            .flex(ratatui::layout::Flex::SpaceBetween)
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
                            .flex(ratatui::layout::Flex::SpaceBetween)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    udp_packet.render(transport_block, frame);
                }
                IpProto::Icmp(icmp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(7), Constraint::Length(13)])
                            .flex(ratatui::layout::Flex::SpaceBetween)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    icmp_packet.render(transport_block, frame);
                }
            },
            IpPacket::V6(ip_packet) => match ip_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(20), Constraint::Length(9)])
                            .flex(ratatui::layout::Flex::SpaceBetween)
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
                            .constraints([Constraint::Length(8), Constraint::Length(9)])
                            .flex(ratatui::layout::Flex::SpaceBetween)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    udp_packet.render(transport_block, frame);
                }
                IpProto::Icmp(icmp_packet) => {
                    let (transport_block, network_block) = {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(7), Constraint::Length(9)])
                            .flex(ratatui::layout::Flex::SpaceBetween)
                            .margin(2)
                            .split(block);

                        (chunks[0], chunks[1])
                    };
                    ip_packet.render(network_block, frame);
                    icmp_packet.render(transport_block, frame);
                }
            },
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Ipv4Packet {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: IpProto,
    pub checksum: u16,
}

impl Ipv4Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(6), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        // Title
        let title = Paragraph::new("IPv4")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    title_block.height / 2 - 1
                } else {
                    title_block.height / 2
                }
            })));

        // IP
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(self.src_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(self.dst_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Internet Header Length", Style::new().bold()),
                Span::from(format!("{} bytes", self.ihl * 4)),
            ]),
            Row::new(vec![
                Span::styled("Type Of Service", Style::new().bold()),
                Span::from(self.tos.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Total Length", Style::new().bold()),
                Span::from(format!("{} bytes", self.total_length)),
            ]),
            Row::new(vec![
                Span::styled("ID", Style::new().bold()),
                Span::from(self.id.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Fragment Offset", Style::new().bold()),
                Span::from(self.fragment_offset.to_string()),
            ]),
            Row::new(vec![
                Span::styled("TTL", Style::new().bold()),
                Span::from(self.ttl.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:0x}", self.checksum)),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().magenta())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );

        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Ipv6Packet {
    pub traffic_class: u8,
    pub flow_label: [u8; 3usize],
    pub payload_length: u16,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub proto: IpProto,
}

impl Ipv6Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(6), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        // Title
        let title = Paragraph::new("IPv6")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    title_block.height / 2 - 1
                } else {
                    title_block.height / 2
                }
            })));

        // IP
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(self.src_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(self.dst_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Traffic Class", Style::new().bold()),
                Span::from(self.traffic_class.to_string()),
            ]),
            // Row::new(vec![
            //     Span::styled("Flow Label", Style::new().bold()),
            //     Span::from(&self.flow_label.to_vec().to_string()),
            // ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.traffic_class.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hop Limit", Style::new().bold()),
                Span::from(self.hop_limit.to_string()),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().magenta())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );

        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

#[derive(Debug, Copy, Clone)]
pub enum IpProto {
    Tcp(TcpPacket),
    Udp(UdpPacket),
    Icmp(IcmpPacket),
}

#[derive(Debug, Copy, Clone)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
}

impl IcmpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(6), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("ICMP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    title_block.height / 2 - 1
                } else {
                    title_block.height / 2
                }
            })));

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(self.icmp_type.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(self.code.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(self.checksum.to_string()),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().yellow())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );

        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

#[derive(Debug, Copy, Clone)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    RedirectMessage,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    BadIPheader,
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply,
    Deprecated,
}

impl Display for IcmpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IcmpType::EchoReply => {
                write!(f, "Echo Reply")
            }
            IcmpType::EchoRequest => {
                write!(f, "Echo Request")
            }
            IcmpType::DestinationUnreachable => {
                write!(f, "Destination Unreachable")
            }
            IcmpType::RedirectMessage => {
                write!(f, "Redirect Message")
            }
            IcmpType::RouterAdvertisement => {
                write!(f, "Router Advertisement")
            }
            IcmpType::RouterSolicitation => {
                write!(f, "Router Solicitation")
            }
            IcmpType::TimeExceeded => {
                write!(f, "Time Exceeded")
            }
            IcmpType::BadIPheader => {
                write!(f, "Bad IP header")
            }
            IcmpType::Timestamp => {
                write!(f, "Timestamp")
            }
            IcmpType::TimestampReply => {
                write!(f, "Timestamp Reply")
            }
            IcmpType::ExtendedEchoRequest => {
                write!(f, "Extended Echo Request")
            }
            IcmpType::ExtendedEchoReply => {
                write!(f, "Extended Echo Reply")
            }
            IcmpType::Deprecated => {
                write!(f, "Deprecated")
            }
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
                IpProto::Icmp(_) => {
                    write!(f, "{} {} ICMP", ipv4_packet.src_ip, ipv4_packet.dst_ip)
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
                IpProto::Icmp(_) => {
                    write!(f, "{} {} ICMP", ipv6_packet.src_ip, ipv6_packet.dst_ip)
                }
            },
        }
    }
}
