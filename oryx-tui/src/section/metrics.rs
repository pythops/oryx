use std::{
    cmp,
    ops::Range,
    sync::{atomic::AtomicBool, Arc, Mutex, RwLock},
    thread,
    time::Duration,
};

use crossterm::event::{Event, KeyCode, KeyEvent};
use regex::Regex;
use tui_input::{backend::crossterm::EventHandler, Input};

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{
        Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, HighlightSpacing,
        Padding, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    },
    Frame,
};

use crate::{
    app::AppResult,
    packet::{
        direction::TrafficDirection,
        network::{IpPacket, IpProto},
        AppPacket, NetworkPacket,
    },
};

#[derive(Debug, Default)]
struct ListState {
    offset: usize,
    selected: Option<usize>,
}

#[derive(Debug)]
pub struct Metrics {
    user_input: UserInput,
    app_packets: Arc<RwLock<Vec<AppPacket>>>,
    metrics: Vec<Arc<Mutex<PortCountMetric>>>,
    terminate: Arc<AtomicBool>,
    state: ListState,
    window_height: usize,
}

#[derive(Debug, Clone, Default)]
struct UserInput {
    input: Input,
    error: Option<String>,
}

impl UserInput {
    fn validate(&mut self) -> AppResult<Range<u16>> {
        self.error = None;
        let re = Regex::new(r"^(?<start>\d{1,5})\-(?<end>\d{1,5})$").unwrap();

        match self.input.value().parse::<u16>() {
            Ok(v) => Ok(Range {
                start: v,
                end: v + 1,
            }),
            Err(_) => {
                let Some(caps) = re.captures(self.input.value()) else {
                    self.error = Some("Invalid Port(s)".to_string());
                    return Err("Validation Error".into());
                };

                let start: u16 = caps["start"].parse()?;
                let end: u16 = caps["end"].parse()?;

                // Empty range
                if start >= end {
                    self.error = Some("Invalid Port Range".to_string());
                    return Err("Validation Error".into());
                }

                Ok(Range { start, end })
            }
        }
    }

    fn clear(&mut self) {
        self.input.reset();
        self.error = None;
    }
}

#[derive(Debug, Default, Clone)]
pub struct PortCountMetric {
    port_range: Range<u16>,
    tcp_count: usize,
    udp_count: usize,
}

impl Metrics {
    pub fn new(packets: Arc<RwLock<Vec<AppPacket>>>) -> Self {
        Self {
            user_input: UserInput::default(),
            app_packets: packets,
            metrics: Vec::new(),
            terminate: Arc::new(AtomicBool::new(false)),
            state: ListState::default(),
            window_height: 0,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect) {
        self.window_height = block.height.saturating_sub(4) as usize / 8;

        let constraints = (0..self.window_height).map(|_| Constraint::Length(8));

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(block.inner(Margin {
                horizontal: 0,
                vertical: 2,
            }));

        let blocks: Vec<_> = chunks
            .iter()
            .map(|b| {
                Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Fill(1),
                        Constraint::Percentage(90),
                        Constraint::Fill(1),
                    ])
                    .flex(ratatui::layout::Flex::SpaceBetween)
                    .split(*b)[1]
            })
            .collect();

        let metrics_to_display = if self.metrics.len() <= self.window_height {
            self.metrics.clone()
        } else {
            self.metrics[self.state.offset..self.state.offset + self.window_height].to_vec()
        };

        for (index, port_count_metric) in metrics_to_display.iter().enumerate() {
            let metric = { port_count_metric.lock().unwrap().clone() };

            let chart = BarChart::default()
                .direction(Direction::Horizontal)
                .bar_width(1)
                .bar_gap(1)
                .data(
                    BarGroup::default().bars(&[
                        Bar::default()
                            .label("TCP".into())
                            .style(Style::new().fg(Color::LightYellow))
                            .value(metric.tcp_count.try_into().unwrap())
                            .value_style(Style::new().fg(Color::Black).bg(Color::LightYellow))
                            .text_value(metric.tcp_count.to_string()),
                        Bar::default()
                            .label("UDP".into())
                            .style(Style::new().fg(Color::LightBlue))
                            .value_style(Style::new().fg(Color::Black).bg(Color::LightBlue))
                            .value(metric.udp_count.try_into().unwrap())
                            .text_value(metric.udp_count.to_string()),
                    ]),
                )
                .max((metric.udp_count + metric.tcp_count) as u64)
                .block(
                    Block::new()
                        .title_alignment(Alignment::Center)
                        .borders(Borders::LEFT)
                        .border_style({
                            if self.state.selected.unwrap() - self.state.offset == index {
                                Style::new().fg(Color::Magenta)
                            } else {
                                Style::new().fg(Color::Gray)
                            }
                        })
                        .border_type({
                            if self.state.selected.unwrap() - self.state.offset == index {
                                BorderType::Thick
                            } else {
                                BorderType::Plain
                            }
                        })
                        .padding(Padding::uniform(1))
                        .title_top({
                            if metric.port_range.len() == 1 {
                                format!("Port: {}", metric.port_range.start)
                            } else {
                                format!(
                                    "Ports: {}-{}",
                                    metric.port_range.start, metric.port_range.end
                                )
                            }
                        }),
                );
            frame.render_widget(
                chart,
                blocks[index].inner(Margin {
                    horizontal: 0,
                    vertical: 1,
                }),
            );
        }

        if self.metrics.len() > self.window_height {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));

            let mut scrollbar_state = ScrollbarState::new(self.metrics.len())
                .position(self.state.offset * self.window_height);
            frame.render_stateful_widget(
                scrollbar,
                block.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        }
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('d') => {
                if self.metrics.is_empty() {
                    return;
                }
                if let Some(selected_item_index) = &mut self.state.selected {
                    self.terminate
                        .store(true, std::sync::atomic::Ordering::Relaxed);

                    let _ = self.metrics.remove(*selected_item_index);

                    self.user_input.clear();

                    self.state.selected = Some(selected_item_index.saturating_sub(1));

                    self.terminate
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }

            KeyCode::Char('k') | KeyCode::Up => {
                let i = match self.state.selected {
                    Some(i) => {
                        if i > self.state.offset {
                            i - 1
                        } else if i == self.state.offset && self.state.offset > 0 {
                            self.state.offset -= 1;
                            i - 1
                        } else {
                            0
                        }
                    }
                    None => 0,
                };

                self.state.selected = Some(i);
            }

            KeyCode::Char('j') | KeyCode::Down => {
                if self.metrics.is_empty() {
                    return;
                }
                let i = match self.state.selected {
                    Some(i) => {
                        if i < self.window_height - 1 {
                            cmp::min(i + 1, self.metrics.len() - 1)
                        } else if self.metrics.len() - 1 == i {
                            i
                        } else {
                            self.state.offset += 1;
                            i + 1
                        }
                    }
                    None => 0,
                };

                self.state.selected = Some(i);
            }
            _ => {}
        }
    }

    pub fn handle_popup_keys(&mut self, key_event: KeyEvent) -> AppResult<()> {
        match key_event.code {
            KeyCode::Esc => {
                self.user_input.clear();
            }

            KeyCode::Enter => {
                let port_range: Range<u16> = self.user_input.validate()?;

                let port_count_metric = Arc::new(Mutex::new(PortCountMetric {
                    port_range: port_range.clone(),
                    tcp_count: 0,
                    udp_count: 0,
                }));

                thread::spawn({
                    let port_count_metric = port_count_metric.clone();
                    let terminate = self.terminate.clone();
                    let packets = self.app_packets.clone();
                    move || {
                        let mut last_index = 0;
                        'main: loop {
                            thread::sleep(Duration::from_millis(100));

                            let app_packets = { packets.read().unwrap().clone() };

                            if app_packets.is_empty() {
                                continue;
                            }
                            let mut metric = port_count_metric.lock().unwrap();
                            for app_packet in app_packets[last_index..].iter() {
                                if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                    break 'main;
                                }
                                if app_packet.direction == TrafficDirection::Ingress {
                                    if let NetworkPacket::Ip(packet) = app_packet.packet {
                                        match packet {
                                            IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                                                IpProto::Tcp(tcp_packet) => {
                                                    if port_range.contains(&tcp_packet.dst_port) {
                                                        metric.tcp_count += 1;
                                                    }
                                                }
                                                IpProto::Udp(udp_packet) => {
                                                    if port_range.contains(&udp_packet.dst_port) {
                                                        metric.udp_count += 1;
                                                    }
                                                }
                                                _ => {}
                                            },
                                            IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                                                IpProto::Tcp(tcp_packet) => {
                                                    if port_range.contains(&tcp_packet.dst_port) {
                                                        metric.tcp_count += 1;
                                                    }
                                                }
                                                IpProto::Udp(udp_packet) => {
                                                    if port_range.contains(&udp_packet.dst_port) {
                                                        metric.udp_count += 1;
                                                    }
                                                }
                                                _ => {}
                                            },
                                        }
                                    }
                                }
                            }

                            last_index = app_packets.len();

                            if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                break 'main;
                            }
                        }
                    }
                });

                self.metrics.push(port_count_metric);
                if self.metrics.len() == 1 {
                    self.state.selected = Some(0);
                }

                self.user_input.clear();
            }

            _ => {
                self.user_input.input.handle_event(&Event::Key(key_event));
            }
        }

        Ok(())
    }

    pub fn render_new_rule_popup(&self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(10), // Form
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Percentage(80),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        let (form_block, message_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Fill(1), Constraint::Length(3)])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .split(block);

            (chunks[0], chunks[1])
        };

        //TODO: Center
        let rows = [
            Row::new(vec![
                Cell::from("Port Packet Counter".to_string())
                    .bg(Color::DarkGray)
                    .fg(Color::White),
                Cell::from(self.user_input.input.value())
                    .bg(Color::DarkGray)
                    .fg(Color::White),
            ]),
            Row::new(vec![Cell::new(""), Cell::new("")]),
            Row::new(vec![
                Cell::new(""),
                Cell::from({
                    if let Some(error) = &self.user_input.error {
                        error.to_string()
                    } else {
                        String::new()
                    }
                })
                .red(),
            ]),
        ];

        let widths = [Constraint::Percentage(49), Constraint::Percentage(49)];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    Line::from("Metric").centered(),
                    Line::from("From").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .highlight_spacing(HighlightSpacing::Always);

        let help_message =
            Text::styled("💡Examples: 443, 8080, 5555-9999", Style::new().dark_gray()).centered();

        frame.render_widget(Clear, block);
        frame.render_widget(
            table,
            form_block.inner(Margin {
                horizontal: 2,
                vertical: 0,
            }),
        );
        frame.render_widget(
            help_message,
            message_block.inner(Margin {
                horizontal: 2,
                vertical: 0,
            }),
        );

        frame.render_widget(
            Block::default()
                .title(" Metrics Explorer ")
                .bold()
                .title_alignment(ratatui::layout::Alignment::Center)
                .borders(Borders::all())
                .border_type(ratatui::widgets::BorderType::Thick)
                .border_style(Style::default().green())
                .padding(Padding::uniform(1)),
            block,
        );
    }
}
