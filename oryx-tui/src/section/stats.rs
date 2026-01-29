use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Bar, BarChart, BarGroup, Block, Padding},
};

use crate::{
    bandwidth::Bandwidth,
    dns::get_hostname,
    packet::{
        NetworkPacket,
        direction::TrafficDirection,
        network::{IpPacket, ip::IpProto},
    },
    packet_store::PacketStore,
};

#[derive(Debug, Default)]
pub struct PacketStats {
    pub total: usize,
    pub filtered: usize,
    pub network: NetworkStats,
    pub transport: TransportStats,
    pub link: LinkStats,
    pub addresses: HashMap<IpAddr, (Option<String>, usize)>,
}

#[derive(Debug)]
pub struct Stats {
    pub packet_stats: Arc<Mutex<PacketStats>>,
    pub bandwidth: Bandwidth,
}

impl Stats {
    pub fn new(packets: PacketStore) -> Self {
        let packet_stats: Arc<Mutex<PacketStats>> = Arc::new(Mutex::new(PacketStats::default()));

        thread::spawn({
            let packet_stats = packet_stats.clone();
            move || {
                let mut last_index: usize = 0;
                loop {
                    thread::sleep(Duration::from_millis(500));

                    if packets.is_empty() {
                        continue;
                    }
                    let mut packet_stats = packet_stats.lock().unwrap();
                    last_index += packets
                        .for_each_range(last_index.., |app_packet| {
                            match app_packet.frame.payload {
                                NetworkPacket::Arp(_) => {
                                    packet_stats.link.arp += 1;
                                }
                                NetworkPacket::Ip(packet) => match packet {
                                    IpPacket::V4(ipv4_packet) => {
                                        packet_stats.network.ipv4 += 1;

                                        if app_packet.direction == TrafficDirection::Egress {
                                            if let Some((_, counts)) = packet_stats
                                                .addresses
                                                .get_mut(&IpAddr::V4(ipv4_packet.dst_ip))
                                            {
                                                *counts += 1;
                                            } else if let Ok(host) =
                                                get_hostname(&IpAddr::V4(ipv4_packet.dst_ip))
                                            {
                                                packet_stats.addresses.insert(
                                                    IpAddr::V4(ipv4_packet.dst_ip),
                                                    (Some(host), 1),
                                                );
                                            } else {
                                                packet_stats.addresses.insert(
                                                    IpAddr::V4(ipv4_packet.dst_ip),
                                                    (None, 1),
                                                );
                                            }
                                        }

                                        match ipv4_packet.proto {
                                            IpProto::Tcp(_) => {
                                                packet_stats.transport.tcp += 1;
                                            }
                                            IpProto::Udp(_) => {
                                                packet_stats.transport.udp += 1;
                                            }
                                            IpProto::Sctp(_) => {
                                                packet_stats.transport.sctp += 1;
                                            }
                                            IpProto::Icmp(_) => {
                                                packet_stats.network.icmpv4 += 1;
                                            }
                                            IpProto::Igmp(_) => {
                                                packet_stats.network.igmp += 1;
                                            }
                                        }
                                    }
                                    IpPacket::V6(ipv6_packet) => {
                                        packet_stats.network.ipv6 += 1;

                                        if app_packet.direction == TrafficDirection::Egress {
                                            if let Some((_, counts)) = packet_stats
                                                .addresses
                                                .get_mut(&IpAddr::V6(ipv6_packet.dst_ip))
                                            {
                                                *counts += 1;
                                            } else if let Ok(host) =
                                                get_hostname(&IpAddr::V6(ipv6_packet.dst_ip))
                                            {
                                                packet_stats.addresses.insert(
                                                    IpAddr::V6(ipv6_packet.dst_ip),
                                                    (Some(host), 1),
                                                );
                                            } else {
                                                packet_stats.addresses.insert(
                                                    IpAddr::V6(ipv6_packet.dst_ip),
                                                    (None, 1),
                                                );
                                            }
                                        }

                                        match ipv6_packet.proto {
                                            IpProto::Tcp(_) => {
                                                packet_stats.transport.tcp += 1;
                                            }
                                            IpProto::Udp(_) => {
                                                packet_stats.transport.udp += 1;
                                            }
                                            IpProto::Sctp(_) => {
                                                packet_stats.transport.sctp += 1;
                                            }
                                            IpProto::Icmp(_) => {
                                                packet_stats.network.icmpv6 += 1;
                                            }
                                            IpProto::Igmp(_) => {
                                                // IGMP is for IPv4 only
                                                unreachable!()
                                            }
                                        }
                                    }
                                },
                            }
                            packet_stats.total += 1;
                            Ok(())
                        })
                        .unwrap();
                }
            }
        });

        Self {
            packet_stats,
            bandwidth: Bandwidth::new(),
        }
    }
    pub fn get_top_10(
        &self,
        addresses: HashMap<IpAddr, (Option<String>, usize)>,
    ) -> Vec<(IpAddr, (Option<String>, usize))> {
        let mut items: Vec<(IpAddr, (Option<String>, usize))> = addresses.into_iter().collect();
        items.sort_by_key(|b| std::cmp::Reverse(b.1.1));
        items.into_iter().take(10).collect()
    }

    pub fn render(&self, frame: &mut Frame, block: Rect, network_interface: &str) {
        let (bandwidth_block, stats_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(1)
                .split(block);
            (chunks[0], chunks[1])
        };

        let (address_block, network_block, transport_block, link_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Max(60),
                        Constraint::Length(12),
                        Constraint::Length(44),
                        Constraint::Length(10),
                    ]
                    .as_ref(),
                )
                .margin(1)
                .flex(Flex::SpaceBetween)
                .split(stats_block);
            (chunks[0], chunks[1], chunks[2], chunks[3])
        };

        let packet_stats = self.packet_stats.lock().unwrap();

        let link_chart = BarChart::default()
            .bar_width(3)
            .bar_gap(1)
            .data(
                BarGroup::default().bars(&[Bar::default()
                    .label("ARP")
                    .style(Style::new().fg(Color::LightYellow))
                    .value_style(Style::new().fg(Color::Black).bg(Color::LightYellow))
                    .text_value(
                        if let Some(val) =
                            (packet_stats.link.arp * 100).checked_div(packet_stats.total)
                        {
                            format!("{val}%")
                        } else {
                            "0%".to_string()
                        },
                    )
                    .value(
                        if let Some(val) =
                            (packet_stats.link.arp * 100).checked_div(packet_stats.total)
                        {
                            val as u64
                        } else {
                            0
                        },
                    )]),
            )
            .block(Block::new().padding(Padding::horizontal(1)))
            .max(100);

        let transport_chart = BarChart::default()
            .bar_width(6)
            .bar_gap(1)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .label("TCP")
                        .style(Style::new().fg(Color::LightBlue))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightBlue))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.transport.tcp * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.transport.tcp * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("UDP")
                        .style(Style::new().fg(Color::LightGreen))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightGreen))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.transport.udp * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.transport.udp * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("SCTP")
                        .style(Style::new().fg(Color::LightRed))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightRed))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.transport.sctp * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.transport.sctp * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("ICMPv4")
                        .style(Style::new().fg(Color::LightCyan))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightCyan))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.network.icmpv4 * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.network.icmpv4 * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("ICMPv6")
                        .style(Style::new().fg(Color::LightCyan))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightCyan))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.network.icmpv6 * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.network.icmpv6 * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("IGMP")
                        .style(Style::new().fg(Color::LightCyan))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightCyan))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.network.igmp * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.network.igmp * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                ]),
            )
            .block(Block::new().padding(Padding::horizontal(1)))
            .max(100);

        let network_chart = BarChart::default()
            .bar_width(4)
            .bar_gap(1)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .label("IPv4")
                        .style(Style::new().fg(Color::LightRed))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightRed))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.network.ipv4 * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.network.ipv4 * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                    Bar::default()
                        .label("IPv6")
                        .style(Style::new().fg(Color::LightCyan))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightCyan))
                        .text_value(
                            if let Some(val) =
                                (packet_stats.network.ipv6 * 100).checked_div(packet_stats.total)
                            {
                                format!("{val}%")
                            } else {
                                "0%".to_string()
                            },
                        )
                        .value(
                            if let Some(val) =
                                (packet_stats.network.ipv6 * 100).checked_div(packet_stats.total)
                            {
                                val as u64
                            } else {
                                0
                            },
                        ),
                ]),
            )
            .block(Block::new().padding(Padding::horizontal(1)))
            .max(100);

        let addresses_chart = BarChart::default()
            .direction(Direction::Horizontal)
            .bar_width(1)
            .bar_gap(1)
            .data(
                BarGroup::default().bars(
                    &self
                        .get_top_10(packet_stats.addresses.clone())
                        .into_iter()
                        .map(|(ip, (host, count))| {
                            Bar::default()
                                .label(Line::from(count.to_string()))
                                .style(Style::new().fg(Color::LightYellow))
                                .value_style(Style::new().fg(Color::Black).bg(Color::LightYellow))
                                .text_value(host.clone().unwrap_or(ip.to_string()))
                                .value(count as u64)
                        })
                        .collect::<Vec<Bar>>(),
                ),
            )
            .block(
                Block::new()
                    .title_alignment(Alignment::Center)
                    .padding(Padding::horizontal(1))
                    .padding(Padding::right(3))
                    .title_bottom("Top visited websites"),
            );

        frame.render_widget(addresses_chart, address_block);
        frame.render_widget(transport_chart, transport_block);
        frame.render_widget(network_chart, network_block);
        frame.render_widget(link_chart, link_block);

        self.bandwidth
            .render(frame, bandwidth_block, network_interface);
    }
}

#[derive(Debug, Default)]
pub struct NetworkStats {
    pub total: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub icmpv4: usize,
    pub icmpv6: usize,
    pub igmp: usize,
}

#[derive(Debug, Default)]
pub struct TransportStats {
    pub tcp: usize,
    pub udp: usize,
    pub sctp: usize,
}

#[derive(Debug, Default)]
pub struct LinkStats {
    pub arp: usize,
}
