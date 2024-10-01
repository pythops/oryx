use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    Frame,
};
use tui_input::backend::crossterm::EventHandler;

use crate::{
    filter::fuzzy::{self, Fuzzy},
    packet::{
        network::{IpPacket, IpProto},
        AppPacket,
    },
};

#[derive(Debug)]
pub struct Inspection {
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub state: TableState,
    pub fuzzy: Arc<Mutex<Fuzzy>>,
    pub manuall_scroll: bool,
    pub packet_end_index: usize,
    pub packet_window_size: usize,
    pub packet_index: Option<usize>,
}

impl Inspection {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Self {
        Self {
            packets: packets.clone(),
            state: TableState::default(),
            fuzzy: Fuzzy::new(packets.clone()),
            manuall_scroll: false,
            packet_end_index: 0,
            packet_window_size: 0,
            packet_index: None,
        }
    }

    pub fn can_show_popup(&mut self) -> bool {
        let packets = self.packets.lock().unwrap();
        let fuzzy = self.fuzzy.lock().unwrap();

        if fuzzy.is_enabled() {
            return !fuzzy.packets.is_empty();
        } else {
            return !packets.is_empty();
        }
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Esc => {
                let mut fuzzy = self.fuzzy.lock().unwrap();
                if fuzzy.is_paused() {
                    if self.manuall_scroll {
                        self.manuall_scroll = false;
                    } else {
                        fuzzy.disable();
                    }
                } else {
                    fuzzy.pause();
                }
            }

            KeyCode::Char('/') => {
                let mut fuzzy = self.fuzzy.lock().unwrap();
                fuzzy.enable();
                fuzzy.unpause();
            }

            KeyCode::Char('j') => {
                self.scroll_down();
            }

            KeyCode::Char('k') => {
                self.scroll_up();
            }

            _ => {
                let mut fuzzy = self.fuzzy.lock().unwrap();
                if !fuzzy.is_paused() {
                    fuzzy
                        .filter
                        .handle_event(&crossterm::event::Event::Key(key_event));
                }
            }
        }
    }

    pub fn scroll_up(&mut self) {
        let app_packets = self.packets.lock().unwrap();
        let mut fuzzy = self.fuzzy.lock().unwrap();
        if !self.manuall_scroll {
            self.manuall_scroll = true;
            // Record the last position. Usefull for selecting the packets to display
            if fuzzy.is_enabled() {
                fuzzy.packet_end_index = fuzzy.packets.len();
            } else {
                self.packet_end_index = app_packets.len();
            }
        }
        if fuzzy.is_enabled() {
            fuzzy.scroll_up(self.packet_window_size);
        } else {
            let i = match self.state.selected() {
                Some(i) => {
                    if i > 1 {
                        i - 1
                    } else if i == 0 && self.packet_end_index > self.packet_window_size {
                        // shit the window by one
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
    }

    pub fn scroll_down(&mut self) {
        let app_packets = self.packets.lock().unwrap();
        let mut fuzzy = self.fuzzy.lock().unwrap();

        if !self.manuall_scroll {
            self.manuall_scroll = true;
            if fuzzy.is_enabled() {
                fuzzy.packet_end_index = fuzzy.packets.len();
            } else {
                self.packet_end_index = app_packets.len();
            }
        }
        if fuzzy.is_enabled() {
            fuzzy.scroll_down(self.packet_window_size);
        } else {
            let i = match self.state.selected() {
                Some(i) => {
                    if i < self.packet_window_size - 1 {
                        i + 1
                    } else if i == self.packet_window_size - 1
                        && app_packets.len() > self.packet_end_index
                    {
                        // shit the window by one
                        self.packet_end_index += 1;
                        i + 1
                    } else {
                        i
                    }
                }
                None => app_packets.len(),
            };

            self.state.select(Some(i));
        }
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect) {
        let app_packets = self.packets.lock().unwrap();
        let mut fuzzy = self.fuzzy.lock().unwrap();
        let fuzzy_packets = fuzzy.clone().packets.clone();

        let pattern = fuzzy.clone();
        let pattern = pattern.filter.value();

        let (packet_block, fuzzy_block) = {
            if fuzzy.is_enabled() {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Fill(1), Constraint::Length(3)])
                    .horizontal_margin(1)
                    .split(block);
                (chunks[0], chunks[1])
            } else {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Fill(1), Constraint::Length(1)])
                    .horizontal_margin(1)
                    .split(block);
                (chunks[0], chunks[1])
            }
        };

        let widths = [
            Constraint::Min(19),    // Source Address
            Constraint::Length(11), // Source Port
            Constraint::Min(19),    // Destination Address
            Constraint::Length(16), // Destination Port
            Constraint::Length(8),  // Protocol
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
                    if let Some(selected_index) = self.state.selected() {
                        self.packet_index = Some(
                            self.packet_end_index.saturating_sub(window_size) + selected_index,
                        );
                    }
                    &app_packets
                        [self.packet_end_index.saturating_sub(window_size)..self.packet_end_index]
                } else {
                    if let Some(selected_index) = self.state.selected() {
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
                self.state.select(Some(packets_to_display.len()));
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
            .block(Block::default().padding(Padding::top(2)));

        if fuzzy.is_enabled() {
            frame.render_stateful_widget(table, packet_block, &mut fuzzy.scroll_state);
        } else {
            frame.render_stateful_widget(table, packet_block, &mut self.state);
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

    pub fn render_packet_infos_popup(&self, frame: &mut Frame) {
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
}
