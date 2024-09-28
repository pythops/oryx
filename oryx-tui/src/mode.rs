use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding},
    Frame,
};

use crate::app::App;
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Packet,
    Stats,
    Alerts,
    Firewall,
}

impl Mode {
    pub fn next(&mut self) {
        *self = match self {
            Mode::Packet => Mode::Stats,
            Mode::Stats => Mode::Alerts,
            Mode::Alerts => Mode::Firewall,
            Mode::Firewall => Mode::Packet,
        }
    }
    pub fn previous(&mut self) {
        *self = match self {
            Mode::Packet => Mode::Firewall,
            Mode::Stats => Mode::Packet,
            Mode::Alerts => Mode::Stats,
            Mode::Firewall => Mode::Alerts,
        };
    }

    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Tab => {
                self.next();
            }
            KeyCode::BackTab => {
                self.previous();
            }

            _ => {
                match self {
                    Mode::Packet => {
                        let fuzzy = app.fuzzy.clone();
                        let mut fuzzy = fuzzy.lock().unwrap();
                        if fuzzy.is_enabled() {
                            match key_event.code {
                                KeyCode::Esc => {
                                    if fuzzy.is_paused() {
                                        if app.manuall_scroll {
                                            app.manuall_scroll = false;
                                        } else {
                                            fuzzy.disable();
                                        }
                                    } else {
                                        fuzzy.pause();
                                    }
                                }
                                _ => {
                                    if !fuzzy.is_paused() && !app.update_filters {
                                        fuzzy
                                            .filter
                                            .handle_event(&crossterm::event::Event::Key(key_event));
                                    }
                                }
                            }
                        } else {
                            match key_event.code {
                                KeyCode::Char('i') => {
                                    if !app.packet_index.is_none() && !fuzzy.packets.is_empty() {
                                        app.show_packet_infos_popup = true;
                                    }
                                }
                                KeyCode::Char('/') => {
                                    if fuzzy.is_enabled() {
                                    } else {
                                        fuzzy.enable();
                                        fuzzy.unpause();
                                        app.is_editing = true;
                                    }
                                }
                                KeyCode::Char('j') | KeyCode::Down => {
                                    if !app.manuall_scroll {
                                        app.manuall_scroll = true;
                                        // Record the last position. Usefull for selecting the packets to display
                                        fuzzy.packet_end_index = fuzzy.packets.len();
                                        let i = match fuzzy.scroll_state.selected() {
                                            Some(i) => {
                                                if i < app.packet_window_size - 1 {
                                                    i + 1
                                                } else if i == app.packet_window_size - 1
                                                    && fuzzy.packets.len() > fuzzy.packet_end_index
                                                {
                                                    // shift the window by one
                                                    fuzzy.packet_end_index += 1;
                                                    i + 1
                                                } else {
                                                    i
                                                }
                                            }
                                            None => fuzzy.packets.len(),
                                        };

                                        fuzzy.scroll_state.select(Some(i));
                                    }
                                }
                                KeyCode::Char('k') | KeyCode::Up => {
                                    if !app.manuall_scroll {
                                        app.manuall_scroll = true;
                                        // Record the last position. Usefull for selecting the packets to display
                                        fuzzy.packet_end_index = fuzzy.packets.len();
                                    }
                                    let i = match fuzzy.scroll_state.selected() {
                                        Some(i) => {
                                            if i > 1 {
                                                i - 1
                                            } else if i == 0
                                                && fuzzy.packet_end_index > app.packet_window_size
                                            {
                                                // shift the window by one
                                                fuzzy.packet_end_index -= 1;
                                                0
                                            } else {
                                                0
                                            }
                                        }
                                        None => fuzzy.packets.len(),
                                    };

                                    fuzzy.scroll_state.select(Some(i));
                                }
                                KeyCode::Char('f') => {
                                    app.update_filters = true;
                                    app.focused_block = UpdateFilterMenuBLock::TransportFilter;
                                    app.focused_block.select();

                                    app.filter.network.selected_protocols =
                                        app.filter.network.applied_protocols.clone();

                                    app.filter.transport.selected_protocols =
                                        app.filter.transport.applied_protocols.clone();

                                    app.filter.link.selected_protocols =
                                        app.filter.link.applied_protocols.clone();

                                    app.filter.traffic_direction.selected_direction =
                                        app.filter.traffic_direction.applied_direction.clone();
                                }
                                KeyCode::Esc => {
                                    if app.show_packet_infos_popup {
                                        app.show_packet_infos_popup = false;
                                    } else if !fuzzy.is_paused() {
                                        fuzzy.pause();
                                        app.is_editing = false;
                                    } else if app.manuall_scroll {
                                        app.manuall_scroll = false;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    Mode::Firewall => match key_event.code {
                        KeyCode::Char('n') => app.is_editing = true,
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, &app: App) {
        self.render_header(frame, area, app.alert.title_span(mode == Mode::Alerts));
        match self {
            Mode::Packet => self.render_packets_mode(frame, mode_block, app),
            Mode::Stats => self.render_stats_mode(frame, mode_block, app),
            Mode::Alerts => app.alert.render(frame, mode_block),
            Mode::Firewall => app.firewall.render(frame, mode_block),
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect, alert_span: Span<'_>) {
        let header = match self {
            Self::Packet => {
                vec![
                    Span::styled(
                        " Packet ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span,
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Stats => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::styled(
                        " Stats ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                    alert_span,
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Alerts => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span.bold(),
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Firewall => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span,
                    Span::styled(
                        " Firewall ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                ]
            }
        };

        frame.render_widget(
            Block::default()
                .title(Line::from(header))
                .title_alignment(Alignment::Left)
                .padding(Padding::top(2))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
            area,
        );
    }
    fn render_stats_mode(self, frame: &mut Frame, block: Rect, &app: App) {
        let stats = app.stats.lock().unwrap();

        let (bandwidth_block, stats_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(2)
                .split(block);
            (chunks[0], chunks[1])
        };

        stats.render(frame, stats_block);

        app.bandwidth.render(
            frame,
            bandwidth_block,
            &app.interface.selected_interface.name.clone(),
        );
    }

    fn render_packets_mode(self, frame: &mut Frame, area: Rect, app: &mut App) {
        let app_packets = app.packets.lock().unwrap();
        let mut fuzzy = app.fuzzy.lock().unwrap();
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
                    .split(area);
                (chunks[0], chunks[1])
            } else {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Fill(1), Constraint::Length(1)])
                    .horizontal_margin(1)
                    .split(area);
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
        let window_size = area.height.saturating_sub(5) as usize;
        app.packet_window_size = window_size;

        // This points always to the end of the window
        if app.packet_end_index < window_size {
            app.packet_end_index = window_size;
        }

        if fuzzy.packet_end_index < window_size {
            fuzzy.packet_end_index = window_size;
        }

        let packets_to_display = match app.manuall_scroll {
            true => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            app.packet_index = Some(
                                fuzzy.packet_end_index.saturating_sub(window_size) + selected_index,
                            );
                        }
                        &fuzzy_packets[fuzzy.packet_end_index.saturating_sub(window_size)
                            ..fuzzy.packet_end_index]
                    } else {
                        if let Some(selected_index) = fuzzy.scroll_state.selected() {
                            app.packet_index = Some(selected_index);
                        } else {
                            app.packet_index = None;
                        }
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    if let Some(selected_index) = app.packets_table_state.selected() {
                        app.packet_index =
                            Some(app.packet_end_index.saturating_sub(window_size) + selected_index);
                    }
                    &app_packets
                        [app.packet_end_index.saturating_sub(window_size)..app.packet_end_index]
                } else {
                    if let Some(selected_index) = app.packets_table_state.selected() {
                        app.packet_index = Some(selected_index);
                    }
                    &app_packets
                }
            }
            false => {
                if fuzzy.is_enabled() & !fuzzy.filter.value().is_empty() {
                    if fuzzy_packets.len() > window_size {
                        app.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        &fuzzy_packets[fuzzy_packets.len().saturating_sub(window_size)..]
                    } else {
                        app.packet_index = Some(fuzzy_packets.len().saturating_sub(1));
                        &fuzzy_packets
                    }
                } else if app_packets.len() > window_size {
                    app.packet_index = Some(app_packets.len().saturating_sub(1));
                    &app_packets[app_packets.len().saturating_sub(window_size)..]
                } else {
                    app.packet_index = Some(app_packets.len().saturating_sub(1));
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
        if !app.manuall_scroll {
            if fuzzy.is_enabled() {
                fuzzy.scroll_state.select(Some(packets_to_display.len()));
            } else {
                app.packets_table_state
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
                        if app.manuall_scroll {
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
            .block(Block::new().padding(Padding::top(2)));

        if fuzzy.is_enabled() {
            frame.render_stateful_widget(table, packet_block, &mut fuzzy.scroll_state);
        } else {
            frame.render_stateful_widget(table, packet_block, &mut app.packets_table_state);
        }

        // Scrollbar

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = if fuzzy.is_enabled() && fuzzy_packets.len() > window_size {
            ScrollbarState::new(fuzzy_packets.len()).position({
                if app.manuall_scroll {
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
                if app.manuall_scroll {
                    if app.packet_end_index == window_size {
                        0
                    } else {
                        app.packet_end_index
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
        // show packet info popup if needed
        if app.show_packet_infos_popup {
            self.render_packet_infos_popup(frame, app);
        }
    }

    fn render_packet_infos_popup(self, frame: &mut Frame, &app: App) {
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

        let fuzzy = app.fuzzy.lock().unwrap();
        let packets = app.packets.lock().unwrap();

        let packet = if fuzzy.is_enabled() {
            fuzzy.packets[app.packet_index.unwrap()]
        } else {
            packets[app.packet_index.unwrap()]
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
