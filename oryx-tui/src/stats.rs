use dns_lookup::lookup_addr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use oryx_common::IpPacket;

use ratatui::layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::{
    widgets::{Bar, BarChart, BarGroup, Block, BorderType, Borders, Padding},
    Frame,
};

use crate::bandwidth::Bandwidth;

#[derive(Debug)]
pub struct Stats {
    pub total: usize,
    pub filtered: usize,
    pub network: NetworkStats,
    pub transport: TransportStats,
    pub addresses: HashMap<Ipv4Addr, (Option<String>, usize)>,
    pub bandwidth: Option<Bandwidth>,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total: 0,
            filtered: 0,
            network: NetworkStats::default(),
            transport: TransportStats::default(),
            addresses: HashMap::with_capacity(1024),
            bandwidth: Bandwidth::new().ok(),
        }
    }
    pub fn get_top_10(&self) -> Vec<(&Ipv4Addr, &(Option<String>, usize))> {
        let mut items: Vec<(&Ipv4Addr, &(Option<String>, usize))> = self.addresses.iter().collect();
        items.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        items.into_iter().take(10).collect()
    }

    pub fn refresh(&mut self, packet: &IpPacket) {
        match packet {
            IpPacket::Tcp(p) => {
                match p.src_ip {
                    std::net::IpAddr::V4(ip) => {
                        self.network.ipv4 += 1;
                        self.transport.tcp += 1;

                        if !ip.is_private() && !ip.is_loopback() {
                            if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                                *counts += 1;
                            } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                                self.addresses.insert(ip, (Some(host), 1));
                            } else {
                                self.addresses.insert(ip, (None, 1));
                            }
                        }
                    }

                    std::net::IpAddr::V6(_) => {
                        self.network.ipv6 += 1;
                        self.transport.tcp += 1;
                    }
                };

                if let std::net::IpAddr::V4(ip) = p.dst_ip {
                    if !ip.is_private() && !ip.is_loopback() {
                        if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                            *counts += 1;
                        } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                            self.addresses.insert(ip, (Some(host), 1));
                        } else {
                            self.addresses.insert(ip, (None, 1));
                        }
                    }
                };
            }
            IpPacket::Udp(p) => {
                match p.src_ip {
                    std::net::IpAddr::V4(ip) => {
                        self.network.ipv4 += 1;
                        self.transport.udp += 1;

                        if !ip.is_private() && !ip.is_loopback() {
                            if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                                *counts += 1;
                            } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                                self.addresses.insert(ip, (Some(host), 1));
                            } else {
                                self.addresses.insert(ip, (None, 1));
                            }
                        }
                    }

                    std::net::IpAddr::V6(_) => {
                        self.network.ipv6 += 1;
                        self.transport.udp += 1;
                    }
                };

                if let std::net::IpAddr::V4(ip) = p.dst_ip {
                    if !ip.is_private() && !ip.is_loopback() {
                        if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                            *counts += 1;
                        } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                            self.addresses.insert(ip, (Some(host), 1));
                        } else {
                            self.addresses.insert(ip, (None, 1));
                        }
                    }
                };
            }
            IpPacket::Icmp(p) => {
                self.network.icmp += 1;

                if let std::net::IpAddr::V4(ip) = p.src_ip {
                    if !ip.is_private() && !ip.is_loopback() {
                        if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                            *counts += 1;
                        } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                            self.addresses.insert(ip, (Some(host), 1));
                        } else {
                            self.addresses.insert(ip, (None, 1));
                        }
                    }
                };

                if let std::net::IpAddr::V4(ip) = p.dst_ip {
                    if !ip.is_private() && !ip.is_loopback() {
                        if let Some((_, counts)) = self.addresses.get_mut(&ip) {
                            *counts += 1;
                        } else if let Ok(host) = lookup_addr(&IpAddr::V4(ip)) {
                            self.addresses.insert(ip, (Some(host), 1));
                        } else {
                            self.addresses.insert(ip, (None, 1));
                        }
                    }
                };
            }
        }

        self.total += 1;
    }

    pub fn render(&self, frame: &mut Frame, stats_block: Rect, network_interface: &str) {
        let (graph_block, barchart_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(2)
                .split(stats_block);
            (chunks[0], chunks[1])
        };

        let (address_block, network_block, transport_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Max(60),
                        Constraint::Length(20),
                        Constraint::Length(12),
                    ]
                    .as_ref(),
                )
                .margin(1)
                .flex(Flex::SpaceBetween)
                .split(barchart_block);
            (chunks[0], chunks[1], chunks[2])
        };

        frame.render_widget(
            Block::default()
                .title({
                    Line::from(vec![
                        Span::from(" Packet ").fg(Color::DarkGray),
                        Span::styled(
                            " Stats ",
                            Style::default().bg(Color::Green).fg(Color::White).bold(),
                        ),
                    ])
                })
                .title_alignment(Alignment::Left)
                .padding(Padding::top(1))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
            stats_block.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );

        let transport_chart = BarChart::default()
            .bar_width(3)
            .bar_gap(4)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .label("TCP".into())
                        .style(Style::new().fg(Color::LightBlue))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightBlue))
                        .text_value(if self.total != 0 {
                            format!("{}%", self.transport.tcp * 100 / self.total)
                        } else {
                            "0%".to_string()
                        })
                        .value(if self.total != 0 {
                            (self.transport.tcp * 100 / self.total) as u64
                        } else {
                            0
                        }),
                    Bar::default()
                        .label("UDP".into())
                        .style(Style::new().fg(Color::LightGreen))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightGreen))
                        .text_value(if self.total != 0 {
                            format!("{}%", self.transport.udp * 100 / self.total)
                        } else {
                            "0%".to_string()
                        })
                        .value(if self.total != 0 {
                            (self.transport.udp * 100 / self.total) as u64
                        } else {
                            0
                        }),
                ]),
            )
            .block(Block::new().padding(Padding::horizontal(1)))
            .max(100);

        let network_chart = BarChart::default()
            .bar_width(4)
            .bar_gap(3)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .label("IPv4".into())
                        .style(Style::new().fg(Color::LightRed))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightRed))
                        .text_value(if self.total != 0 {
                            format!("{}%", self.network.ipv4 * 100 / self.total)
                        } else {
                            "0%".to_string()
                        })
                        .value(if self.total != 0 {
                            (self.network.ipv4 * 100 / self.total) as u64
                        } else {
                            0
                        }),
                    Bar::default()
                        .label("IPv6".into())
                        .style(Style::new().fg(Color::LightCyan))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightCyan))
                        .text_value(if self.total != 0 {
                            format!("{}%", self.network.ipv6 * 100 / self.total)
                        } else {
                            "0%".to_string()
                        })
                        .value(if self.total != 0 {
                            (self.network.ipv6 * 100 / self.total) as u64
                        } else {
                            0
                        }),
                    Bar::default()
                        .label("Icmp".into())
                        .style(Style::new().fg(Color::LightMagenta))
                        .value_style(Style::new().fg(Color::Black).bg(Color::LightMagenta))
                        .text_value(if self.total != 0 {
                            format!("{}%", self.network.icmp * 100 / self.total)
                        } else {
                            "0%".to_string()
                        })
                        .value(if self.total != 0 {
                            (self.network.icmp * 100 / self.total) as u64
                        } else {
                            0
                        }),
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
                        .get_top_10()
                        .into_iter()
                        .map(|(ip, (host, count))| {
                            Bar::default()
                                .label(Line::from(count.to_string()))
                                .style(Style::new().fg(Color::LightYellow))
                                .value_style(Style::new().fg(Color::Black).bg(Color::LightYellow))
                                .text_value(host.clone().unwrap_or(ip.to_string()))
                                .value(*count as u64)
                        })
                        .collect::<Vec<Bar>>(),
                ),
            )
            .block(
                Block::new()
                    .title_alignment(Alignment::Center)
                    .padding(Padding::horizontal(1))
                    .padding(Padding::right(3))
                    .title_bottom("Top visited websites (Ipv4 only)"),
            );

        frame.render_widget(addresses_chart, address_block);
        frame.render_widget(transport_chart, transport_block);
        frame.render_widget(network_chart, network_block);

        if let Some(bandwidth) = &self.bandwidth {
            bandwidth.render(frame, graph_block, network_interface)
        }
    }
}

#[derive(Debug, Default)]
pub struct NetworkStats {
    pub total: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub icmp: usize,
}

#[derive(Debug, Default)]
pub struct TransportStats {
    pub tcp: usize,
    pub udp: usize,
}
