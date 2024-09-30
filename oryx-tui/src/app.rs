use oryx_common::RawPacket;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    Frame,
};
use std::{
    error,
    sync::{Arc, Mutex},
    thread,
};
use tui_big_text::{BigText, PixelSize};

use crate::{alert::Alert, bandwidth::Bandwidth, filter::fuzzy, packet::network::IpProto};
use crate::{filter::fuzzy::Fuzzy, notification::Notification};
use crate::{filter::Filter, help::Help};
use crate::{interface::Interface, packet::AppPacket};
use crate::{packet::network::IpPacket, stats::Stats};

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
    Alerts,
}

#[derive(Debug)]
pub struct DataEventHandler {
    pub sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub handler: thread::JoinHandle<()>,
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub help: Help,
    pub focused_block: FocusedBlock,
    // used in setup to know which block to  fall into after discarding help
    pub previous_focused_block: FocusedBlock,
    pub interface: Interface,
    pub filter: Filter,
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
    pub bandwidth: Bandwidth,
    pub show_packet_infos_popup: bool,
    pub packet_index: Option<usize>,
    pub alert: Alert,
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

        Self {
            running: true,
            help: Help::new(),
            focused_block: FocusedBlock::Interface,
            previous_focused_block: FocusedBlock::Interface,
            interface: Interface::default(),
            filter: Filter::new(),
            start_sniffing: false,
            packets: packets.clone(),
            packets_table_state: TableState::default(),
            fuzzy: Fuzzy::new(packets.clone()),
            notifications: Vec::new(),
            manuall_scroll: false,
            mode: Mode::Packet,
            stats,
            packet_end_index: 0,
            packet_window_size: 0,
            update_filters: false,
            data_channel_sender: sender,
            bandwidth: Bandwidth::new(),
            show_packet_infos_popup: false,
            packet_index: None,
            alert: Alert::new(packets.clone()),
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        // Setup
        if !self.start_sniffing {
            let (interface_block, filter_block, start_block) = {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(self.interface.interfaces.len() as u16 + 6),
                        Constraint::Fill(1),
                        Constraint::Length(4),
                    ])
                    .margin(1)
                    .flex(Flex::SpaceAround)
                    .split(frame.area());
                (chunks[0], chunks[1], chunks[2])
            };

            // interfaces
            self.interface
                .render_on_setup(frame, interface_block, &self.focused_block);

            // Filters
            self.filter
                .render_on_setup(frame, filter_block, &self.focused_block);

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
            self.interface.render_on_sniffing(frame, interface_block);

            // Filters
            self.filter.render_on_sniffing(frame, filter_block);

            // Packets/Stats
            match self.mode {
                Mode::Packet => {
                    self.render_packets_mode(frame, mode_block);
                    if self.show_packet_infos_popup {
                        self.render_packet_infos_popup(frame);
                    }
                }
                Mode::Stats => self.render_stats_mode(frame, mode_block),
                Mode::Alerts => self.alert.render(frame, mode_block),
            }

            // Update filters

            if self.update_filters {
                self.filter.update(frame, mode_block, &self.focused_block);
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
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            self.packet_index = Some(
                                fuzzy.packet_end_index.saturating_sub(window_size) + selected_index,
                            );
                        }
                        &fuzzy_packets[fuzzy.packet_end_index.saturating_sub(window_size)
                            ..fuzzy.packet_end_index]
                    } else {
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            self.packet_index = Some(selected_index);
                        } else {
                            self.packet_index = None;
                        }
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    if let Some(selected_index) = self.packets_table_state.selected() {
                        self.packet_index = Some(
                            self.packet_end_index.saturating_sub(window_size) + selected_index,
                        );
                    }
                    &app_packets
                        [self.packet_end_index.saturating_sub(window_size)..self.packet_end_index]
                } else {
                    if let Some(selected_index) = self.packets_table_state.selected() {
                        self.packet_index = Some(selected_index);
                    }
                    &app_packets
                }
            }
            false => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        self.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        &fuzzy_packets[fuzzy_packets.len().saturating_sub(window_size)..]
                    } else {
                        self.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    self.packet_index = Some(app_packets.len().saturating_sub(1));
                    &app_packets[app_packets.len().saturating_sub(window_size)..]
                } else {
                    self.packet_index = Some(app_packets.len().saturating_sub(1));
                    &app_packets
                }
            }
        };

        // Style the packets
        let packets: Vec<Row> = if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
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
                        IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                            IpProto::Tcp(p) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, "TCP".to_string()).cyan(),
                            ]),
                            IpProto::Udp(p) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, "UDP".to_string()).cyan(),
                            ]),
                            IpProto::Icmp(_) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string()).blue(),
                                Cell::from(Line::from("-").centered()).yellow(),
                                fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string()).blue(),
                                Cell::from(Line::from("-").centered()).yellow(),
                                fuzzy::highlight(pattern, "ICMP".to_string()).cyan(),
                            ]),
                        },
                        IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                            IpProto::Tcp(p) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, "TCP".to_string()).cyan(),
                            ]),
                            IpProto::Udp(p) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string()).blue(),
                                fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                fuzzy::highlight(pattern, "UDP".to_string()).cyan(),
                            ]),
                            IpProto::Icmp(_) => Row::new(vec![
                                fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string()).blue(),
                                Cell::from(Line::from("-").centered()).yellow(),
                                fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string()).blue(),
                                Cell::from(Line::from("-").centered()).yellow(),
                                fuzzy::highlight(pattern, "ICMP".to_string()).cyan(),
                            ]),
                        },
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
                        IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                            IpProto::Tcp(p) => Row::new(vec![
                                Span::from(ipv4_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.src_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from(ipv4_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.dst_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from("TCP".to_string()).into_centered_line().cyan(),
                            ]),
                            IpProto::Udp(p) => Row::new(vec![
                                Span::from(ipv4_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.src_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from(ipv4_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.dst_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from("UDP".to_string()).into_centered_line().cyan(),
                            ]),
                            IpProto::Icmp(_) => Row::new(vec![
                                Span::from(ipv4_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from("-").into_centered_line().yellow(),
                                Span::from(ipv4_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from("-").into_centered_line().yellow(),
                                Span::from("ICMP".to_string()).into_centered_line().cyan(),
                            ]),
                        },
                        IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                            IpProto::Tcp(p) => Row::new(vec![
                                Span::from(ipv6_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.src_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from(ipv6_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.dst_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from("TCP".to_string()).into_centered_line().cyan(),
                            ]),
                            IpProto::Udp(p) => Row::new(vec![
                                Span::from(ipv6_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.src_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from(ipv6_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from(p.dst_port.to_string())
                                    .into_centered_line()
                                    .yellow(),
                                Span::from("UDP".to_string()).into_centered_line().cyan(),
                            ]),
                            IpProto::Icmp(_) => Row::new(vec![
                                Span::from(ipv6_packet.src_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from("-").into_centered_line().yellow(),
                                Span::from(ipv6_packet.dst_ip.to_string())
                                    .into_centered_line()
                                    .blue(),
                                Span::from("-").into_centered_line().yellow(),
                                Span::from("ICMP".to_string()).into_centered_line().cyan(),
                            ]),
                        },
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
                            self.alert.title_span(),
                        ])
                    })
                    .title_alignment(Alignment::Left)
                    .padding(Padding::top(1))
                    .borders(Borders::ALL)
                    .style(Style::default())
                    .border_type(BorderType::default())
                    .border_style(Style::default().green()),
            );

        if fuzzy.is_enabled() {
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
                    if fuzzy.packet_end_index == window_size {
                        0
                    } else {
                        fuzzy.packet_end_index
                    }
                } else {
                    fuzzy.packets.len()
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

        if fuzzy.is_enabled() {
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
                        self.alert.title_span(),
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

        self.bandwidth.render(
            frame,
            bandwidth_block,
            &self.interface.selected_interface.name.clone(),
        );
    }

    fn render_packet_infos_popup(&self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(36),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Max(80),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        let fuzzy = self.fuzzy.lock().unwrap();
        let packets = self.packets.lock().unwrap();

        let packet = if fuzzy.is_enabled() {
            fuzzy.packets[self.packet_index.unwrap()]
        } else {
            packets[self.packet_index.unwrap()]
        };

        frame.render_widget(Clear, block);
        frame.render_widget(
            Block::new()
                .title(" Packet Infos 󰋼  ")
                .title_style(Style::new().bold().green())
                .title_alignment(Alignment::Center)
                .borders(Borders::all())
                .border_style(Style::new().green())
                .border_type(BorderType::Thick),
            block,
        );
        match packet {
            AppPacket::Ip(ip_packet) => ip_packet.render(block, frame),
            AppPacket::Arp(arp_packet) => arp_packet.render(block, frame),
        };
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

        self.alert.check();
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}
