use oryx_common::ip::IpPacket;
use oryx_common::protocols::{
    Protocol, NB_LINK_PROTOCOL, NB_NETWORK_PROTOCOL, NB_TRANSPORT_PROTOCOL,
};
use oryx_common::{AppPacket, RawPacket};
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
use std::borrow::Borrow;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{error, thread};
use tui_big_text::{BigText, PixelSize};

use crate::bandwidth::Bandwidth;
use crate::filters::direction::TrafficDirectionFilter;
use crate::filters::fuzzy::{self, Fuzzy};
use crate::filters::link::LinkFilter;
use crate::filters::network::NetworkFilter;
use crate::filters::transport::TransportFilter;
use crate::help::Help;
use crate::interface::Interface;
use crate::notification::Notification;
use crate::stats::Stats;

pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

pub const TICK_RATE: u64 = 40;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FocusedBlock {
    Interface,
    TransportFilter,
    NetworkFilter,
    LinkFilter,
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
pub struct DataEventHandler {
    pub sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub handler: thread::JoinHandle<()>,
}

// let x = Protocol::NetworkProtocol(Tcp)

#[derive(Debug, Clone)]
pub struct FilterChannel {
    pub sender: kanal::Sender<(Protocol, bool)>,
    pub receiver: kanal::Receiver<(Protocol, bool)>,
}

impl FilterChannel {
    pub fn new() -> Self {
        let (sender, receiver) = kanal::unbounded();
        Self { sender, receiver }
    }
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
    pub transport_filter: TransportFilter,
    pub link_filter: LinkFilter,
    pub traffic_direction_filter: TrafficDirectionFilter,
    pub ingress_filter_channel: FilterChannel,
    pub egress_filter_channel: FilterChannel,
    pub start_sniffing: bool,
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub packets_table_state: TableState,
    pub fuzzy: Arc<Mutex<Fuzzy>>,
    pub notifications: Vec<Notification>,
    pub manuall_scroll: bool,
    pub mode: Mode,
    pub stats: Arc<Mutex<Stats>>,
    pub packet_end_index: usize,
    pub packet_window_size: usize,
    pub update_filters: bool,
    pub data_channel_sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub bandwidth: Arc<Mutex<Option<Bandwidth>>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let packets = Arc::new(Mutex::new(Vec::with_capacity(AppPacket::LEN * 1024 * 1024)));
        let stats = Arc::new(Mutex::new(Stats::default()));
        let fuzzy = Arc::new(Mutex::new(Fuzzy::default()));

        let network_filter = NetworkFilter::new();
        let transport_filter = TransportFilter::new();
        let link_filter = LinkFilter::new();

        let (sender, receiver) = kanal::unbounded();

        thread::spawn({
            let packets = packets.clone();
            let stats = stats.clone();

            move || loop {
                if let Ok(raw_packet) = receiver.recv() {
                    App::process(packets.clone(), stats.clone(), AppPacket::from(raw_packet));
                }
            }
        });

        let bandwidth = Arc::new(Mutex::new(Bandwidth::new().ok()));

        thread::spawn({
            let bandwidth = bandwidth.clone();
            move || loop {
                thread::sleep(Duration::from_secs(1));
                {
                    let mut bandwidth = bandwidth.lock().unwrap();
                    if bandwidth.is_some() {
                        let _ = bandwidth.as_mut().unwrap().refresh();
                    }
                }
            }
        });

        thread::spawn({
            let fuzzy = fuzzy.clone();
            let packets = packets.clone();
            move || {
                let mut last_index = 0;
                let mut pattern = String::new();
                loop {
                    thread::sleep(Duration::from_millis(TICK_RATE));
                    let packets = packets.lock().unwrap();
                    let mut fuzzy = fuzzy.lock().unwrap();

                    if fuzzy.is_enabled() && !fuzzy.filter.value().is_empty() {
                        let current_pattern = fuzzy.filter.value().to_owned();
                        if current_pattern != pattern {
                            fuzzy.find(packets.as_slice());
                            pattern = current_pattern;
                            last_index = packets.len();
                        } else {
                            fuzzy.append(&packets.as_slice()[last_index..]);
                            last_index = packets.len();
                        }
                    }
                }
            }
        });

        Self {
            running: true,
            help: Help::new(),
            focused_block: FocusedBlock::Interface,
            previous_focused_block: FocusedBlock::Interface,
            interface: Interface::default(),
            network_filter,
            transport_filter,
            link_filter,
            traffic_direction_filter: TrafficDirectionFilter::default(),
            ingress_filter_channel: FilterChannel::new(),
            egress_filter_channel: FilterChannel::new(),
            start_sniffing: false,
            packets,
            packets_table_state: TableState::default(),
            fuzzy,
            notifications: Vec::new(),
            manuall_scroll: false,
            mode: Mode::Packet,
            stats,
            packet_end_index: 0,
            packet_window_size: 0,
            update_filters: false,
            data_channel_sender: sender,
            bandwidth,
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        // Setup
        if !self.start_sniffing {
            let (
                interface_block,
                transport_filter_block,
                network_filter_block,
                link_filter_block,
                traffic_direction_block,
                start_block,
            ) = {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(self.interface.interfaces.len() as u16 + 6),
                        Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                        Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                        Constraint::Length(NB_LINK_PROTOCOL + 4),
                        Constraint::Length(6),
                        Constraint::Length(4),
                    ])
                    .margin(1)
                    .flex(Flex::SpaceAround)
                    .split(frame.area());
                (
                    chunks[0], chunks[1], chunks[2], chunks[3], chunks[4], chunks[5],
                )
            };

            // interfaces
            self.interface
                .render(frame, interface_block, &self.focused_block);

            // Filters
            self.network_filter
                .render(frame, network_filter_block, &self.focused_block);

            self.transport_filter
                .render(frame, transport_filter_block, &self.focused_block);

            self.link_filter
                .render(frame, link_filter_block, &self.focused_block);

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
                    .constraints([Constraint::Length(8), Constraint::Fill(1)])
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
                    Span::styled("Mac", Style::new().bold()),
                    Span::from(
                        self.interface
                            .selected_interface
                            .mac_address
                            .clone()
                            .unwrap_or("-".to_string()),
                    ),
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
            let filters = {
                [
                    Row::new(vec![
                        Line::styled("Transport", Style::new().bold()),
                        Line::from_iter(TransportFilter::new().selected_protocols.iter().map(
                            |filter| {
                                if self.transport_filter.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_red(),
                                    )
                                }
                            },
                        )),
                    ]),
                    Row::new(vec![
                        Line::styled("Network", Style::new().bold()),
                        Line::from_iter(NetworkFilter::new().selected_protocols.iter().map(
                            |filter| {
                                if self.network_filter.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_red(),
                                    )
                                }
                            },
                        )),
                    ]),
                    Row::new(vec![
                        Line::styled("Link", Style::new().bold()),
                        Line::from_iter(LinkFilter::new().selected_protocols.iter().map(
                            |filter| {
                                if self.link_filter.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_red(),
                                    )
                                }
                            },
                        )),
                    ]),
                    Row::new(vec![
                        Line::styled("Direction", Style::new().bold()),
                        Line::from_iter(
                            TrafficDirectionFilter::default()
                                .selected_direction
                                .iter()
                                .map(|filter| {
                                    if self
                                        .traffic_direction_filter
                                        .applied_direction
                                        .contains(filter)
                                    {
                                        Span::styled(
                                            format!("󰞁 {}  ", filter),
                                            Style::default().light_green(),
                                        )
                                    } else {
                                        Span::styled(
                                            format!("󰿝 {}  ", filter),
                                            Style::default().light_red(),
                                        )
                                    }
                                }),
                        ),
                    ]),
                ]
            };

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
                        Constraint::Length(40),
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
                    transport_filter_block,
                    network_filter_block,
                    link_filter_block,
                    traffic_direction_block,
                    apply_block,
                ) = {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                            Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                            Constraint::Length(NB_LINK_PROTOCOL + 4),
                            Constraint::Length(6),
                            Constraint::Length(4),
                        ])
                        .margin(1)
                        .flex(Flex::SpaceBetween)
                        .split(block);
                    (chunks[0], chunks[1], chunks[2], chunks[3], chunks[4])
                };

                frame.render_widget(Clear, block);
                frame.render_widget(
                    Block::new()
                        .borders(Borders::all())
                        .border_type(BorderType::Thick)
                        .border_style(Style::default().green()),
                    block,
                );

                self.transport_filter
                    .render(frame, transport_filter_block, &self.focused_block);

                self.network_filter
                    .render(frame, network_filter_block, &self.focused_block);

                self.link_filter
                    .render(frame, link_filter_block, &self.focused_block);

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
        let app_packets = self.packets.lock().unwrap();
        let mut fuzzy = self.fuzzy.lock().unwrap();
        let fuzzy_packets = fuzzy.clone().packets.clone();

        //TODO: ugly
        let pattern = fuzzy.clone();
        let pattern = pattern.filter.value();

        let (packet_block, fuzzy_block) = {
            if fuzzy.is_enabled() {
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

        if fuzzy.packet_end_index < window_size {
            fuzzy.packet_end_index = window_size;
        }

        let packets_to_display = match self.manuall_scroll {
            true => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        &fuzzy_packets[fuzzy.packet_end_index.saturating_sub(window_size)
                            ..fuzzy.packet_end_index]
                    } else {
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    &app_packets
                        [self.packet_end_index.saturating_sub(window_size)..self.packet_end_index]
                } else {
                    &app_packets
                }
            }
            false => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        &fuzzy_packets[fuzzy_packets.len().saturating_sub(window_size)..]
                    } else {
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    &app_packets[app_packets.len().saturating_sub(window_size)..]
                } else {
                    &app_packets
                }
            }
        };

        // Style the packets
        let packets: Vec<Row> = if fuzzy.is_enabled() & !fuzzy.borrow().filter.value().is_empty() {
            packets_to_display
                .iter()
                .map(|app_packet| match app_packet {
                    AppPacket::Arp(packet) => Row::new(vec![
                        fuzzy::highlight(pattern, packet.src_mac.to_string()).blue(),
                        Cell::from(Line::from("-").centered()).yellow(),
                        fuzzy::highlight(pattern, packet.dst_mac.to_string()).blue(),
                        Cell::from(Line::from("-").centered()).yellow(),
                        fuzzy::highlight(pattern, "ARP".to_string()).cyan(),
                    ]),
                    AppPacket::Ip(packet) => match packet {
                        IpPacket::Tcp(p) => Row::new(vec![
                            fuzzy::highlight(pattern, p.src_ip.to_string()).blue(),
                            fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                            fuzzy::highlight(pattern, p.dst_ip.to_string()).blue(),
                            fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                            fuzzy::highlight(pattern, "TCP".to_string()).cyan(),
                        ]),
                        IpPacket::Udp(p) => Row::new(vec![
                            fuzzy::highlight(pattern, p.src_ip.to_string()).blue(),
                            fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                            fuzzy::highlight(pattern, p.dst_ip.to_string()).blue(),
                            fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                            fuzzy::highlight(pattern, "UDP".to_string()).cyan(),
                        ]),
                        IpPacket::Icmp(p) => Row::new(vec![
                            fuzzy::highlight(pattern, p.src_ip.to_string()).blue(),
                            Cell::from(Line::from("-").centered()).yellow(),
                            fuzzy::highlight(pattern, p.dst_ip.to_string()).blue(),
                            Cell::from(Line::from("-").centered()).yellow(),
                            fuzzy::highlight(pattern, "ICMP".to_string()).cyan(),
                        ]),
                    },
                })
                .collect()
        } else {
            packets_to_display
                .iter()
                .map(|app_packet| match app_packet {
                    AppPacket::Arp(packet) => Row::new(vec![
                        Span::from(packet.src_mac.to_string())
                            .into_centered_line()
                            .blue(),
                        Span::from("-").into_centered_line().yellow(),
                        Span::from(packet.dst_mac.to_string())
                            .into_centered_line()
                            .blue(),
                        Span::from("-").into_centered_line().yellow(),
                        Span::from("ARP".to_string()).into_centered_line().cyan(),
                    ]),
                    AppPacket::Ip(packet) => match packet {
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
                    },
                })
                .collect()
        };

        // Always select the last packet
        if !self.manuall_scroll {
            if fuzzy.is_enabled() {
                fuzzy.scroll_state.select(Some(packets_to_display.len()));
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

        if fuzzy.borrow().is_enabled() {
            frame.render_stateful_widget(table, packet_block, &mut fuzzy.scroll_state);
        } else {
            frame.render_stateful_widget(table, packet_block, &mut self.packets_table_state);
        }

        // Scrollbar

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = if fuzzy.is_enabled() && fuzzy_packets.len() > window_size {
            ScrollbarState::new(fuzzy_packets.len()).position({
                if self.manuall_scroll {
                    if fuzzy.borrow().packet_end_index == window_size {
                        0
                    } else {
                        fuzzy.borrow().packet_end_index
                    }
                } else {
                    fuzzy.borrow().packets.len()
                }
            })
        } else if !fuzzy.is_enabled() && app_packets.len() > window_size {
            ScrollbarState::new(app_packets.len()).position({
                if self.manuall_scroll {
                    if self.packet_end_index == window_size {
                        0
                    } else {
                        self.packet_end_index
                    }
                } else {
                    app_packets.len()
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

        if fuzzy.borrow().is_enabled() {
            let fuzzy = Paragraph::new(format!("> {}", fuzzy.filter.value()))
                .alignment(Alignment::Left)
                .style(Style::default().white())
                .block(
                    Block::new()
                        .borders(Borders::all())
                        .title(" Search  ")
                        .title_style({
                            if fuzzy.is_paused() {
                                Style::default().bold().green()
                            } else {
                                Style::default().bold().yellow()
                            }
                        })
                        .border_style({
                            if fuzzy.is_paused() {
                                Style::default().green()
                            } else {
                                Style::default().yellow()
                            }
                        }),
                );

            frame.render_widget(fuzzy, fuzzy_block);
        }
    }

    pub fn render_stats_mode(&mut self, frame: &mut Frame, block: Rect) {
        let stats = self.stats.lock().unwrap();
        let mut bandwidth = self.bandwidth.lock().unwrap();

        let (bandwidth_block, stats_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
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
            block.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );

        stats.render(frame, stats_block);

        if bandwidth.is_some() {
            bandwidth.as_mut().unwrap().render(
                frame,
                bandwidth_block,
                &self.interface.selected_interface.name.clone(),
            );
        }
    }

    pub fn process(
        packets: Arc<Mutex<Vec<AppPacket>>>,
        stats: Arc<Mutex<Stats>>,
        app_packet: AppPacket,
    ) {
        let mut packets = packets.lock().unwrap();

        if packets.len() == packets.capacity() {
            packets.reserve(1024 * 1024);
        }

        packets.push(app_packet);

        let mut stats = stats.lock().unwrap();
        stats.refresh(&app_packet);
    }

    pub fn tick(&mut self) {
        self.notifications.iter_mut().for_each(|n| n.ttl -= 1);
        self.notifications.retain(|n| n.ttl > 0);
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}
