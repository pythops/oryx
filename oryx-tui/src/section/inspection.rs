use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
};
use tui_input::backend::crossterm::EventHandler;

use crate::{
    app::AppResult,
    export,
    filter::fuzzy::{self, Fuzzy},
    notification::{Notification, NotificationLevel},
    packet::{
        AppPacket, NetworkPacket,
        eth_frame::EthFrameHeader,
        network::{IpPacket, ip::IpProto},
    },
    packet_store::PacketStore,
};

#[derive(Debug)]
pub struct Inspection {
    pub packets: PacketStore,
    pub state: TableState,
    pub fuzzy: Arc<Mutex<Fuzzy>>,
    pub manual_scroll: bool,
    pub packet_end_index: usize,
    pub packet_window_size: usize,
    pub packet_index: Option<usize>,
    pub packets_display_buffer: Vec<AppPacket>,
}

impl Inspection {
    pub fn new(packets: PacketStore) -> Self {
        Self {
            packets: packets.clone(),
            state: TableState::default(),
            fuzzy: Fuzzy::new(packets.clone()),
            manual_scroll: false,
            packet_end_index: 0,
            packet_window_size: 0,
            packet_index: None,
            packets_display_buffer: Vec::with_capacity(128),
        }
    }

    pub fn can_show_popup(&mut self) -> bool {
        let fuzzy = self.fuzzy.lock().unwrap();
        if fuzzy.is_enabled() {
            !fuzzy.packets.is_empty()
        } else {
            !self.packets.is_empty()
        }
    }

    pub fn handle_keys(
        &mut self,
        key_event: KeyEvent,
        event_sender: kanal::Sender<crate::event::Event>,
    ) -> AppResult<()> {
        let fuzzy_is_enabled = { self.fuzzy.lock().unwrap().is_enabled() };

        if fuzzy_is_enabled {
            let mut fuzzy = self.fuzzy.lock().unwrap();
            match key_event.code {
                KeyCode::Esc => {
                    if !fuzzy.is_paused() {
                        fuzzy.pause();
                    } else if self.manual_scroll {
                        self.manual_scroll = false;
                    } else {
                        fuzzy.disable();
                    }
                }
                _ => {
                    if !fuzzy.is_paused() {
                        fuzzy
                            .filter
                            .handle_event(&crossterm::event::Event::Key(key_event));
                    } else {
                        match key_event.code {
                            KeyCode::Char('j') | KeyCode::Down => {
                                if !self.manual_scroll {
                                    self.manual_scroll = true;
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                }
                                fuzzy.scroll_down(self.packet_window_size);
                            }

                            KeyCode::Char('/') => {
                                fuzzy.enable();
                                fuzzy.unpause();
                            }

                            KeyCode::Char('k') | KeyCode::Up => {
                                if !self.manual_scroll {
                                    self.manual_scroll = true;
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                }
                                fuzzy.scroll_up(self.packet_window_size);
                            }

                            _ => {}
                        }
                    }
                }
            }
        } else {
            match key_event.code {
                KeyCode::Esc => {
                    if self.manual_scroll {
                        self.manual_scroll = false;
                    }
                }

                KeyCode::Char('j') | KeyCode::Down => {
                    self.scroll_down();
                }

                KeyCode::Char('/') => {
                    let mut fuzzy = self.fuzzy.lock().unwrap();
                    fuzzy.enable();
                    fuzzy.unpause();
                }

                KeyCode::Char('k') | KeyCode::Up => {
                    self.scroll_up();
                }

                KeyCode::Char('s') => {
                    if self.packets.is_empty() {
                        Notification::send(
                            "There is no packets".to_string(),
                            NotificationLevel::Info,
                            event_sender,
                        )?;
                    } else {
                        match export::export(&self.packets) {
                            Ok(_) => {
                                Notification::send(
                                    "Packets exported to ~/oryx directory".to_string(),
                                    NotificationLevel::Info,
                                    event_sender,
                                )?;
                            }
                            Err(e) => {
                                Notification::send(
                                    e.to_string(),
                                    NotificationLevel::Error,
                                    event_sender,
                                )?;
                            }
                        }
                    }
                }

                _ => {}
            }
        }
        Ok(())
    }

    pub fn scroll_up(&mut self) {
        if !self.manual_scroll {
            self.manual_scroll = true;
            // Record the last position. Useful for selecting the packets to display
            self.packet_end_index = self.packets.len();
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i > 1 {
                    i - 1
                } else if i == 0 && self.packet_end_index > self.packet_window_size {
                    // shift the window by one
                    self.packet_end_index -= 1;
                    0
                } else {
                    0
                }
            }
            None => self.packet_window_size,
        };

        self.state.select(Some(i));
    }

    pub fn scroll_down(&mut self) {
        let packets_len = self.packets.len();
        if !self.manual_scroll {
            self.manual_scroll = true;
            self.packet_end_index = packets_len;
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i < self.packet_window_size - 1 {
                    i + 1
                } else if i == self.packet_window_size - 1 && packets_len > self.packet_end_index {
                    // shift the window by one
                    self.packet_end_index += 1;
                    i + 1
                } else {
                    i
                }
            }
            None => packets_len,
        };

        self.state.select(Some(i));
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect) {
        let mut fuzzy = self.fuzzy.lock().unwrap();
        let fuzzy_packets = fuzzy.clone().packets.clone();

        let pattern = fuzzy.clone();
        let pattern = pattern.filter.value();

        let (packet_block, fuzzy_block) = {
            if fuzzy.is_enabled() {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Fill(1),
                        Constraint::Length(3),
                    ])
                    .horizontal_margin(1)
                    .split(block);
                (chunks[1], chunks[2])
            } else {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Fill(1),
                        Constraint::Length(1),
                    ])
                    .horizontal_margin(1)
                    .split(block);
                (chunks[1], chunks[2])
            }
        };

        let widths = [
            Constraint::Min(19),    // Source Address
            Constraint::Length(11), // Source Port
            Constraint::Min(19),    // Destination Address
            Constraint::Length(16), // Destination Port
            Constraint::Length(8),  // Protocol
            Constraint::Length(10), // Pid
            Constraint::Length(3),  // manual scroll sign
        ];

        // The size of the window where to display packets
        let window_size = block.height.saturating_sub(5) as usize;
        self.packet_window_size = window_size;

        // This points always to the end of the window
        if self.packet_end_index < window_size {
            self.packet_end_index = window_size;
        }

        if fuzzy.packet_end_index < window_size {
            fuzzy.packet_end_index = window_size;
        }

        let packets_len = self.packets.len();
        let pdb = &mut self.packets_display_buffer;
        pdb.clear();
        match self.manual_scroll {
            true => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            self.packet_index = Some(
                                fuzzy.packet_end_index.saturating_sub(window_size) + selected_index,
                            );
                        }
                        pdb.extend_from_slice(
                            &fuzzy_packets[fuzzy.packet_end_index.saturating_sub(window_size)
                                ..fuzzy.packet_end_index],
                        );
                    } else {
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            self.packet_index = Some(selected_index);
                        } else {
                            self.packet_index = None;
                        }
                        pdb.extend_from_slice(&fuzzy_packets)
                    }
                } else if packets_len > window_size {
                    if let Some(selected_index) = self.state.selected() {
                        self.packet_index = Some(
                            self.packet_end_index.saturating_sub(window_size) + selected_index,
                        );
                    }
                    self.packets.write_range_into(
                        self.packet_end_index.saturating_sub(window_size)..self.packet_end_index,
                        pdb,
                    );
                } else {
                    if let Some(selected_index) = self.state.selected() {
                        self.packet_index = Some(selected_index);
                    }
                    self.packets.write_range_into(0..packets_len, pdb);
                }
            }
            false => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        self.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        pdb.extend_from_slice(
                            &fuzzy_packets[fuzzy_packets.len().saturating_sub(window_size)..],
                        )
                    } else {
                        self.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        pdb.extend_from_slice(&fuzzy_packets);
                    }
                } else if packets_len > window_size {
                    let start_index = packets_len.saturating_sub(window_size);
                    self.packet_index = Some(packets_len.saturating_sub(1));
                    self.packets.write_range_into(start_index..packets_len, pdb);
                } else {
                    self.packet_index = Some(packets_len.saturating_sub(1));
                    self.packets.write_range_into(0..packets_len, pdb);
                }
            }
        };

        // Style the packets
        let packets: Vec<Row> = if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
            pdb.iter()
                .map(|app_packet| {
                    let pid = match app_packet.pid {
                        Some(pid) => fuzzy::highlight(pattern, pid.to_string()).blue(),
                        None => Cell::from(Line::from("-").centered()).yellow(),
                    };

                    match app_packet.frame.payload {
                        NetworkPacket::Arp(packet) => Row::new(vec![
                            fuzzy::highlight(pattern, packet.src_mac.to_string()).blue(),
                            Cell::from(Line::from("-").centered()).yellow(),
                            fuzzy::highlight(pattern, packet.dst_mac.to_string()).blue(),
                            Cell::from(Line::from("-").centered()).yellow(),
                            fuzzy::highlight(pattern, "ARP".to_string()).cyan(),
                            pid,
                        ]),
                        NetworkPacket::Ip(packet) => match packet {
                            IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                                IpProto::Tcp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "TCP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Udp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "UDP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Sctp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "SCTP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Icmp(_) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, "ICMPv4".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Igmp(_) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv4_packet.src_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, ipv4_packet.dst_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, "IGMP".to_string()).cyan(),
                                    pid,
                                ]),
                            },
                            IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                                IpProto::Tcp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "TCP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Udp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "UDP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Sctp(p) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.src_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string())
                                        .blue(),
                                    fuzzy::highlight(pattern, p.dst_port.to_string()).yellow(),
                                    fuzzy::highlight(pattern, "SCTP".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Icmp(_) => Row::new(vec![
                                    fuzzy::highlight(pattern, ipv6_packet.src_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, ipv6_packet.dst_ip.to_string())
                                        .blue(),
                                    Cell::from(Line::from("-").centered()).yellow(),
                                    fuzzy::highlight(pattern, "ICMPv6".to_string()).cyan(),
                                    pid,
                                ]),
                                IpProto::Igmp(_) => {
                                    // IGMP is for Ipv4 only
                                    unreachable!()
                                }
                            },
                        },
                    }
                })
                .collect()
        } else {
            pdb.iter()
                .map(|app_packet| {
                    let pid = match app_packet.pid {
                        Some(pid) => Span::from(pid.to_string()).into_centered_line().cyan(),
                        None => Span::from("-").into_centered_line().yellow(),
                    };

                    match app_packet.frame.payload {
                        NetworkPacket::Arp(packet) => Row::new(vec![
                            Span::from(packet.src_mac.to_string())
                                .into_centered_line()
                                .blue(),
                            Span::from("-").into_centered_line().yellow(),
                            Span::from(packet.dst_mac.to_string())
                                .into_centered_line()
                                .blue(),
                            Span::from("-").into_centered_line().yellow(),
                            Span::from("ARP".to_string()).into_centered_line().cyan(),
                            pid,
                        ]),
                        NetworkPacket::Ip(packet) => match packet {
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
                                    pid,
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
                                    pid,
                                ]),
                                IpProto::Sctp(p) => Row::new(vec![
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
                                    Span::from("SCTP".to_string()).into_centered_line().cyan(),
                                    pid,
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
                                    Span::from("ICMPv4".to_string()).into_centered_line().cyan(),
                                    pid,
                                ]),
                                IpProto::Igmp(_) => Row::new(vec![
                                    Span::from(ipv4_packet.src_ip.to_string())
                                        .into_centered_line()
                                        .blue(),
                                    Span::from("-").into_centered_line().yellow(),
                                    Span::from(ipv4_packet.dst_ip.to_string())
                                        .into_centered_line()
                                        .blue(),
                                    Span::from("-").into_centered_line().yellow(),
                                    Span::from("IGMP".to_string()).into_centered_line().cyan(),
                                    pid,
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
                                    pid,
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
                                    pid,
                                ]),
                                IpProto::Sctp(p) => Row::new(vec![
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
                                    Span::from("SCTP".to_string()).into_centered_line().cyan(),
                                    pid,
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
                                    Span::from("ICMPv6".to_string()).into_centered_line().cyan(),
                                    pid,
                                ]),
                                IpProto::Igmp(_) => {
                                    // IGMP is for IPv4 only
                                    unreachable!()
                                }
                            },
                        },
                    }
                })
                .collect()
        };

        // Always select the last packet
        if !self.manual_scroll {
            if fuzzy.is_enabled() {
                fuzzy.scroll_state.select(Some(pdb.len()));
            } else {
                self.state.select(Some(pdb.len()));
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
                    Line::from("Pid").centered(),
                    {
                        if self.manual_scroll {
                            Line::from("󰹆").centered().yellow()
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
            .row_highlight_style(Style::new().bg(ratatui::style::Color::DarkGray))
            .highlight_spacing(HighlightSpacing::Always)
            .block(Block::default().padding(Padding::uniform(1)));

        if fuzzy.is_enabled() {
            frame.render_stateful_widget(table, packet_block, &mut fuzzy.scroll_state);
        } else {
            frame.render_stateful_widget(table, packet_block, &mut self.state);
        }

        // Scrollbar

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let app_packets_len = self.packets.len();
        let mut scrollbar_state = if fuzzy.is_enabled() && fuzzy_packets.len() > window_size {
            ScrollbarState::new(fuzzy_packets.len()).position({
                if self.manual_scroll {
                    if fuzzy.packet_end_index == window_size {
                        0
                    } else {
                        fuzzy.packet_end_index
                    }
                } else {
                    fuzzy.packets.len()
                }
            })
        } else if !fuzzy.is_enabled() && app_packets_len > window_size {
            ScrollbarState::new(app_packets_len).position({
                if self.manual_scroll {
                    if self.packet_end_index == window_size {
                        0
                    } else {
                        self.packet_end_index
                    }
                } else {
                    app_packets_len
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
                        .borders(Borders::TOP)
                        .title(" Search  ")
                        .padding(Padding::horizontal(1))
                        .title_style({
                            if fuzzy.is_paused() {
                                Style::default().bold().yellow()
                            } else {
                                Style::default().bold().green()
                            }
                        })
                        .border_type({
                            if fuzzy.is_paused() {
                                BorderType::default()
                            } else {
                                BorderType::Thick
                            }
                        })
                        .border_style({
                            if fuzzy.is_paused() {
                                Style::default().yellow()
                            } else {
                                Style::default().green()
                            }
                        }),
                );

            frame.render_widget(fuzzy, fuzzy_block);
        }
    }

    pub fn render_packet_infos_popup(&self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(50),
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

        let app_packet = if fuzzy.is_enabled() {
            fuzzy.packets[self.packet_index.unwrap()]
        } else {
            self.packets.get(self.packet_index.unwrap()).unwrap()
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

        match app_packet.frame.payload {
            NetworkPacket::Ip(ip_packet) => {
                let (network_packet_block, eth_frame_block) = {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Fill(1), Constraint::Length(8)])
                        .flex(ratatui::layout::Flex::Center)
                        .horizontal_margin(4)
                        .split(block);

                    (chunks[0], chunks[1])
                };

                EthFrameHeader::from(app_packet.frame.header).render(eth_frame_block, frame);
                ip_packet.render(network_packet_block, frame)
            }
            NetworkPacket::Arp(arp_packet) => {
                let (arp_block, eth_frame_block) = {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Fill(1),
                            Constraint::Percentage(50),
                            Constraint::Length(6),
                            Constraint::Fill(1),
                        ])
                        .flex(ratatui::layout::Flex::Center)
                        .margin(2)
                        .split(block);

                    (chunks[1], chunks[2])
                };

                arp_packet.render(arp_block, frame);
                EthFrameHeader::from(app_packet.frame.header).render(eth_frame_block, frame);
            }
        };
    }
}
