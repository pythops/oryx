use oryx_common::IpPacket;
use ratatui::layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::Clear;
use ratatui::{
    widgets::{
        Block, BorderType, Borders, Cell, HighlightSpacing, Padding, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    Frame,
};
use std::error;
use std::net::IpAddr;
use tui_big_text::{BigText, PixelSize};

use crate::filters::direction::TrafficDirectionFilter;
use crate::filters::fuzzy::{self, Fuzzy};
use crate::filters::network::{NetworkFilter, NetworkProtocol, NB_NETWORK_PROTOCOL};
use crate::filters::transport::{TransportFilter, TransportProtocol, NB_TRANSPORT_PROTOCOL};
use crate::help::Help;
use crate::interface::Interface;
use crate::notification::Notification;
use crate::stats::Stats;

pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FocusedBlock {
    Interface,
    TransportFilter,
    NetworkFilter,
    TrafficDirection,
    Start,
    Help,
    Main,
}

#[derive(Debug, PartialEq)]
pub enum Mode {
    Packet,
    Stats,
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub help: Help,
    pub focused_block: FocusedBlock,
    // used in setup to know which block to  fall into after discarding help
    pub previous_focused_block: FocusedBlock,
    pub interface: Interface,
    pub network_filter: NetworkFilter,
    pub transort_filter: TransportFilter,
    pub traffic_direction_filter: TrafficDirectionFilter,
    pub start_sniffing: bool,
    pub packets: Vec<IpPacket>,
    pub packets_table_state: TableState,
    pub fuzzy: Fuzzy,
    pub notifications: Vec<Notification>,
    pub manuall_scroll: bool,
    pub mode: Mode,
    pub stats: Stats,
    pub packet_end_index: usize,
    pub packet_window_size: usize,
    pub update_filters: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            help: Help::new(),
            focused_block: FocusedBlock::Interface,
            previous_focused_block: FocusedBlock::Interface,
            interface: Interface::default(),
            network_filter: NetworkFilter::default(),
            transort_filter: TransportFilter::default(),
            traffic_direction_filter: TrafficDirectionFilter::default(),
            start_sniffing: false,
            packets: Vec::with_capacity(40 * 1024 * 1024),
            packets_table_state: TableState::default(),
            fuzzy: Fuzzy::default(),
            notifications: Vec::new(),
            manuall_scroll: false,
            mode: Mode::Packet,
            stats: Stats::default(),
            packet_end_index: 0,
            packet_window_size: 0,
            update_filters: false,
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        // Setup
        if !self.start_sniffing {
            let (
                interface_block,
                network_filter_block,
                transport_filter_block,
                traffic_direction_block,
                start_block,
            ) = {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(self.interface.interfaces.len() as u16 + 6),
                        Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                        Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                        Constraint::Length(6),
                        Constraint::Length(4),
                    ])
                    .margin(1)
                    .flex(Flex::SpaceAround)
                    .split(frame.area());
                (chunks[0], chunks[1], chunks[2], chunks[3], chunks[4])
            };

            // interfaces
            self.interface
                .render(frame, interface_block, &self.focused_block);

            // Filters
            self.network_filter
                .render(frame, network_filter_block, &self.focused_block);

            self.transort_filter
                .render(frame, transport_filter_block, &self.focused_block);

            self.traffic_direction_filter.render(
                frame,
                traffic_direction_block,
                &self.focused_block,
            );

            // Start Button
            let start = BigText::builder()
                .pixel_size(PixelSize::Sextant)
                .style(if self.focused_block == FocusedBlock::Start {
                    Style::default().white().bold()
                } else {
                    Style::default().dark_gray()
                })
                .lines(vec!["START".into()])
                .centered()
                .build();
            frame.render_widget(start, start_block);
        } else {
            // Sniffing
            let (settings_block, mode_block) = {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(7), Constraint::Fill(1)])
                    .split(frame.area());
                (chunks[0], chunks[1])
            };
            // Settings
            let (filter_block, interface_block) = {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .margin(1)
                    .split(settings_block);
                (chunks[0], chunks[1])
            };

            // Interface
            let widths = [Constraint::Length(4), Constraint::Fill(1)];

            let interface_infos = [
                Row::new(vec![
                    Span::styled("Name", Style::new().bold()),
                    Span::from(self.interface.selected_interface.name.clone()),
                ]),
                Row::new(vec![
                    Span::styled("IPv4", Style::new().bold()),
                    Span::from(
                        self.interface
                            .selected_interface
                            .addresses
                            .iter()
                            .find(|a| matches!(a, IpAddr::V4(_) | IpAddr::V6(_)))
                            .unwrap()
                            .to_string(),
                    ),
                ]),
                Row::new(vec![
                    Span::styled("IPv6", Style::new().bold()),
                    Span::from({
                        match self
                            .interface
                            .selected_interface
                            .addresses
                            .iter()
                            .find(|a| matches!(a, IpAddr::V6(_)))
                        {
                            Some(ip) => ip.to_string(),
                            None => "-".to_string(),
                        }
                    }),
                ]),
            ];

            let interface_table = Table::new(interface_infos, widths).column_spacing(3).block(
                Block::default()
                    .title(" Interface 󰲝 ")
                    .title_style(Style::default().bold().green())
                    .title_alignment(Alignment::Center)
                    .padding(Padding::horizontal(2))
                    .borders(Borders::ALL)
                    .style(Style::default())
                    .border_type(BorderType::default())
                    .border_style(Style::default().green()),
            );

            // Filters
            let widths = [Constraint::Length(10), Constraint::Fill(1)];
            let filters = [
                Row::new(vec![
                    Span::styled("Network", Style::new().bold()),
                    Span::from(
                        self.network_filter
                            .applied_protocols
                            .iter()
                            .map(|filter| filter.to_string())
                            .collect::<Vec<String>>()
                            .join(" "),
                    ),
                ]),
                Row::new(vec![
                    Span::styled("Transport", Style::new().bold()),
                    Span::from(
                        self.transort_filter
                            .applied_protocols
                            .iter()
                            .map(|filter| filter.to_string())
                            .collect::<Vec<String>>()
                            .join(" "),
                    ),
                ]),
                Row::new(vec![
                    Span::styled("Direction", Style::new().bold()),
                    Span::from(
                        self.traffic_direction_filter
                            .applied_direction
                            .iter()
                            .map(|direction| direction.to_string())
                            .collect::<Vec<String>>()
                            .join(" "),
                    ),
                ]),
            ];

            let filter_table = Table::new(filters, widths).column_spacing(3).block(
                Block::default()
                    .title(" Filters 󱪤 ")
                    .title_style(Style::default().bold().green())
                    .title_alignment(Alignment::Center)
                    .padding(Padding::horizontal(2))
                    .borders(Borders::ALL)
                    .style(Style::default())
                    .border_type(BorderType::default())
                    .border_style(Style::default().green()),
            );

            frame.render_widget(interface_table, interface_block);
            frame.render_widget(filter_table, filter_block);

            // Packets/Stats
            match self.mode {
                Mode::Packet => self.render_packets_mode(frame, mode_block),
                Mode::Stats => self.render_stats_mode(frame, mode_block),
            }

            // Update filters

            if self.update_filters {
                let layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Fill(1),
                        Constraint::Length(32),
                        Constraint::Fill(1),
                    ])
                    .flex(ratatui::layout::Flex::SpaceBetween)
                    .split(mode_block);

                let block = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Fill(1),
                        Constraint::Length(60),
                        Constraint::Fill(1),
                    ])
                    .flex(ratatui::layout::Flex::SpaceBetween)
                    .split(layout[1])[1];

                let (
                    network_filter_block,
                    transport_filter_block,
                    traffic_direction_block,
                    apply_block,
                ) = {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                            Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                            Constraint::Length(6),
                            Constraint::Length(4),
                        ])
                        .margin(1)
                        .flex(Flex::SpaceBetween)
                        .split(block);
                    (chunks[0], chunks[1], chunks[2], chunks[3])
                };

                frame.render_widget(Clear, block);
                frame.render_widget(
                    Block::new()
                        .borders(Borders::all())
                        .border_type(BorderType::Thick)
                        .border_style(Style::default().green()),
                    block,
                );
                self.network_filter
                    .render(frame, network_filter_block, &self.focused_block);

                self.transort_filter
                    .render(frame, transport_filter_block, &self.focused_block);

                self.traffic_direction_filter.render(
                    frame,
                    traffic_direction_block,
                    &self.focused_block,
                );

                let apply = BigText::builder()
                    .pixel_size(PixelSize::Sextant)
                    .style(if self.focused_block == FocusedBlock::Start {
                        Style::default().white().bold()
                    } else {
                        Style::default().dark_gray()
                    })
                    .lines(vec!["APPLY".into()])
                    .centered()
                    .build();
                frame.render_widget(apply, apply_block);
            }
        }
    }

    pub fn render_packets_mode(&mut self, frame: &mut Frame, packet_mode_block: Rect) {
        let (packet_block, fuzzy_block) = {
            if self.fuzzy.is_enabled() {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Fill(1), Constraint::Length(3)])
                    .horizontal_margin(1)
                    .split(packet_mode_block);
                (chunks[0], chunks[1])
            } else {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Fill(1), Constraint::Length(1)])
                    .horizontal_margin(1)
                    .split(packet_mode_block);
                (chunks[0], chunks[1])
            }
        };

        let widths = [
            Constraint::Min(19),    // Source Address
            Constraint::Length(11), // Source Port
            Constraint::Min(19),    // Destination Address
            Constraint::Length(16), // Destination Port
            Constraint::Length(8),  // Protocol
            Constraint::Length(2),  // Protocol
        ];

        // The size of the window where to display packets
        let window_size = packet_mode_block.height.saturating_sub(5) as usize;
        self.packet_window_size = window_size;

        // This points always to the end of the window
        if self.packet_end_index < window_size {
            self.packet_end_index = window_size;
        }

        if self.fuzzy.packet_end_index < window_size {
            self.fuzzy.packet_end_index = window_size;
        }

        let packets_to_display = match self.manuall_scroll {
            true => {
                if self.fuzzy.is_enabled() & !self.fuzzy.filter.value().is_empty() {
                    if self.fuzzy.packets.len() > window_size {
                        &self.fuzzy.packets.as_slice()[self
                            .fuzzy
                            .packet_end_index
                            .saturating_sub(window_size)
                            ..self.fuzzy.packet_end_index]
                    } else {
                        &self.fuzzy.packets
                    }
                } else if self.packets.len() > window_size {
                    &self.packets
                        [self.packet_end_index.saturating_sub(window_size)..self.packet_end_index]
                } else {
                    &self.packets
                }
            }
            false => {
                if self.fuzzy.is_enabled() & !self.fuzzy.filter.value().is_empty() {
                    if self.fuzzy.packets.len() > window_size {
                        &self.fuzzy.packets[self.fuzzy.packets.len().saturating_sub(window_size)..]
                    } else {
                        &self.fuzzy.packets
                    }
                } else if self.packets.len() > window_size {
                    &self.packets[self.packets.len().saturating_sub(window_size)..]
                } else {
                    &self.packets
                }
            }
        };

        // Style the packets
        let packets: Vec<Row> = if self.fuzzy.is_enabled() & !self.fuzzy.filter.value().is_empty() {
            packets_to_display
                .iter()
                .map(|packet| match packet {
                    IpPacket::Tcp(p) => Row::new(vec![
                        fuzzy::highlight(self.fuzzy.filter.value(), p.src_ip.to_string()).blue(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.src_port.to_string())
                            .yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.dst_ip.to_string()).blue(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.dst_port.to_string())
                            .yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), "TCP".to_string()).cyan(),
                    ]),
                    IpPacket::Udp(p) => Row::new(vec![
                        fuzzy::highlight(self.fuzzy.filter.value(), p.src_ip.to_string()).blue(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.src_port.to_string())
                            .yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.dst_ip.to_string()).blue(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.dst_port.to_string())
                            .yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), "UDP".to_string()).cyan(),
                    ]),
                    IpPacket::Icmp(p) => Row::new(vec![
                        fuzzy::highlight(self.fuzzy.filter.value(), p.src_ip.to_string()).blue(),
                        Cell::from(Line::from("-").centered()).yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), p.dst_ip.to_string()).blue(),
                        Cell::from(Line::from("-").centered()).yellow(),
                        fuzzy::highlight(self.fuzzy.filter.value(), "ICMP".to_string()).cyan(),
                    ]),
                })
                .collect()
        } else {
            packets_to_display
                .iter()
                .map(|packet| match packet {
                    IpPacket::Tcp(p) => Row::new(vec![
                        Span::from(p.src_ip.to_string()).into_centered_line().blue(),
                        Span::from(p.src_port.to_string())
                            .into_centered_line()
                            .yellow(),
                        Span::from(p.dst_ip.to_string()).into_centered_line().blue(),
                        Span::from(p.dst_port.to_string())
                            .into_centered_line()
                            .yellow(),
                        Span::from("TCP".to_string()).into_centered_line().cyan(),
                    ]),
                    IpPacket::Udp(p) => Row::new(vec![
                        Span::from(p.src_ip.to_string()).into_centered_line().blue(),
                        Span::from(p.src_port.to_string())
                            .into_centered_line()
                            .yellow(),
                        Span::from(p.dst_ip.to_string()).into_centered_line().blue(),
                        Span::from(p.dst_port.to_string())
                            .into_centered_line()
                            .yellow(),
                        Span::from("UDP".to_string()).into_centered_line().cyan(),
                    ]),
                    IpPacket::Icmp(p) => Row::new(vec![
                        Span::from(p.src_ip.to_string()).into_centered_line().blue(),
                        Span::from("-").into_centered_line().yellow(),
                        Span::from(p.dst_ip.to_string()).into_centered_line().blue(),
                        Span::from("-").into_centered_line().yellow(),
                        Span::from("ICMP".to_string()).into_centered_line().cyan(),
                    ]),
                })
                .collect()
        };

        // Always select the last packet
        if !self.manuall_scroll {
            if self.fuzzy.is_enabled() {
                self.fuzzy
                    .scroll_state
                    .select(Some(packets_to_display.len()));
            } else {
                self.packets_table_state
                    .select(Some(packets_to_display.len()));
            }
        }

        let table = Table::new(packets, widths)
            .header(
                Row::new(vec![
                    Line::from("Source Address").centered(),
                    Line::from("Source Port").centered(),
                    Line::from("Destination Address").centered(),
                    Line::from("Destination Port").centered(),
                    Line::from("Protocol").centered(),
                    {
                        if self.manuall_scroll {
                            Line::from(" ").centered().yellow()
                        } else {
                            Line::from("").centered()
                        }
                    },
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray))
            .highlight_spacing(HighlightSpacing::Always)
            .block(
                Block::default()
                    .title({
                        Line::from(vec![
                            Span::styled(
                                " Packet ",
                                Style::default().bg(Color::Green).fg(Color::White).bold(),
                            ),
                            Span::from(" Stats ").fg(Color::DarkGray),
                        ])
                    })
                    .title_alignment(Alignment::Left)
                    .padding(Padding::top(1))
                    .borders(Borders::ALL)
                    .style(Style::default())
                    .border_type(BorderType::default())
                    .border_style(Style::default().green()),
            );

        if self.fuzzy.is_enabled() {
            frame.render_stateful_widget(table, packet_block, &mut self.fuzzy.scroll_state);
        } else {
            frame.render_stateful_widget(table, packet_block, &mut self.packets_table_state);
        }

        // Scrollbar

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state =
            if self.fuzzy.is_enabled() && self.fuzzy.packets.len() > window_size {
                ScrollbarState::new(self.fuzzy.packets.len()).position({
                    if self.manuall_scroll {
                        if self.fuzzy.packet_end_index == window_size {
                            0
                        } else {
                            self.fuzzy.packet_end_index
                        }
                    } else {
                        self.fuzzy.packets.len()
                    }
                })
            } else if !self.fuzzy.is_enabled() && self.packets.len() > window_size {
                ScrollbarState::new(self.packets.len()).position({
                    if self.manuall_scroll {
                        if self.packet_end_index == window_size {
                            0
                        } else {
                            self.packet_end_index
                        }
                    } else {
                        self.packets.len()
                    }
                })
            } else {
                ScrollbarState::default()
            };

        frame.render_stateful_widget(
            scrollbar,
            packet_block.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );

        if self.fuzzy.is_enabled() {
            let fuzzy = Paragraph::new(format!("> {}", self.fuzzy.filter.value()))
                .alignment(Alignment::Left)
                .style(Style::default().white())
                .block(
                    Block::new()
                        .borders(Borders::all())
                        .title(" Search  ")
                        .title_style({
                            if self.fuzzy.is_paused() {
                                Style::default().bold().green()
                            } else {
                                Style::default().bold().yellow()
                            }
                        })
                        .border_style({
                            if self.fuzzy.is_paused() {
                                Style::default().green()
                            } else {
                                Style::default().yellow()
                            }
                        }),
                );

            frame.render_widget(fuzzy, fuzzy_block);
        }
    }

    pub fn render_stats_mode(&mut self, frame: &mut Frame, stats_block: Rect) {
        self.stats
            .render(frame, stats_block, &self.interface.selected_interface.name);
    }

    pub fn process(&mut self, packet: IpPacket) {
        if self.packets.len() == self.packets.capacity() {
            self.packets.reserve(1024 * 1024);
        }
        match packet {
            IpPacket::Tcp(p) => {
                if self
                    .transort_filter
                    .applied_protocols
                    .contains(&TransportProtocol::TCP)
                {
                    match p.src_ip {
                        core::net::IpAddr::V6(_) => {
                            if self
                                .network_filter
                                .applied_protocols
                                .contains(&NetworkProtocol::Ipv6)
                            {
                                self.packets.push(packet);
                            }
                        }
                        core::net::IpAddr::V4(_) => {
                            if self
                                .network_filter
                                .applied_protocols
                                .contains(&NetworkProtocol::Ipv4)
                            {
                                self.packets.push(packet);
                            }
                        }
                    }
                }
            }
            IpPacket::Udp(p) => {
                if self
                    .transort_filter
                    .applied_protocols
                    .contains(&TransportProtocol::UDP)
                {
                    match p.src_ip {
                        core::net::IpAddr::V6(_) => {
                            if self
                                .network_filter
                                .applied_protocols
                                .contains(&NetworkProtocol::Ipv6)
                            {
                                self.packets.push(packet);
                            }
                        }
                        core::net::IpAddr::V4(_) => {
                            if self
                                .network_filter
                                .applied_protocols
                                .contains(&NetworkProtocol::Ipv4)
                            {
                                self.packets.push(packet);
                            }
                        }
                    }
                }
            }
            IpPacket::Icmp(_) => {
                if self
                    .network_filter
                    .applied_protocols
                    .contains(&NetworkProtocol::Icmp)
                {
                    self.packets.push(packet);
                }
            }
        }

        self.stats.refresh(&packet);
    }

    pub fn tick(&mut self) {
        self.notifications.iter_mut().for_each(|n| n.ttl -= 1);
        self.notifications.retain(|n| n.ttl > 0);

        // Even when not updating the pattern, new packets are still comming
        if self.fuzzy.is_enabled() {
            self.fuzzy.find(&self.packets);
        }

        if let Some(bandwidth) = &mut self.stats.bandwidth {
            bandwidth.refresh().ok();
        }
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}
