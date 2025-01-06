use std::{
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
    time::Duration,
};

use crossterm::event::{Event, KeyCode, KeyEvent};
use tui_input::{backend::crossterm::EventHandler, Input};

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{
        Bar, BarChart, BarGroup, Block, Borders, Cell, Clear, HighlightSpacing, Padding, Row, Table,
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

#[derive(Debug)]
pub struct Metrics {
    user_input: Input,
    app_packets: Arc<Mutex<Vec<AppPacket>>>,
    port_count: Option<Arc<Mutex<PortCountMetric>>>,
    terminate: Arc<AtomicBool>,
}

#[derive(Debug, Default, Clone)]
pub struct PortCountMetric {
    port: u16,
    tcp_count: usize,
    udp_count: usize,
}

impl Metrics {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Self {
        Self {
            user_input: Input::default(),
            app_packets: packets,
            port_count: None,
            terminate: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Fill(1)])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(block);

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Percentage(90),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        if let Some(port_count_metric) = &self.port_count {
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
                        .padding(Padding::vertical(1))
                        .title_top(format!("Port: {}", metric.port)),
                );
            frame.render_widget(chart, block);
        }
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        if let KeyCode::Char('d') = key_event.code {
            self.terminate
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.port_count = None;
            self.user_input.reset();
            self.terminate
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn handle_popup_keys(
        &mut self,
        key_event: KeyEvent,
        _sender: kanal::Sender<crate::event::Event>,
    ) -> AppResult<()> {
        match key_event.code {
            KeyCode::Esc => {
                self.user_input.reset();
            }

            KeyCode::Enter => {
                //TODO: validate input
                let port: u16 = self.user_input.value().parse().unwrap();
                let port_count = Arc::new(Mutex::new(PortCountMetric {
                    port,
                    tcp_count: 0,
                    udp_count: 0,
                }));

                thread::spawn({
                    let port_count = port_count.clone();
                    let terminate = self.terminate.clone();
                    let packets = self.app_packets.clone();
                    move || {
                        let mut last_index = 0;
                        'main: loop {
                            thread::sleep(Duration::from_millis(100));

                            let app_packets = { packets.lock().unwrap().clone() };

                            if app_packets.is_empty() {
                                continue;
                            }
                            let mut metric = port_count.lock().unwrap();
                            for app_packet in app_packets[last_index..].iter() {
                                if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                    break 'main;
                                }
                                if app_packet.direction == TrafficDirection::Ingress {
                                    if let NetworkPacket::Ip(packet) = app_packet.packet {
                                        match packet {
                                            IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                                                IpProto::Tcp(tcp_packet) => {
                                                    if tcp_packet.dst_port == port {
                                                        metric.tcp_count += 1;
                                                    }
                                                }
                                                IpProto::Udp(udp_packet) => {
                                                    if udp_packet.dst_port == port {
                                                        metric.udp_count += 1;
                                                    }
                                                }
                                                _ => {}
                                            },
                                            IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                                                IpProto::Tcp(tcp_packet) => {
                                                    if tcp_packet.dst_port == port {
                                                        metric.tcp_count += 1;
                                                    }
                                                }
                                                IpProto::Udp(udp_packet) => {
                                                    if udp_packet.dst_port == port {
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

                self.port_count = Some(port_count);
            }

            _ => {
                self.user_input.handle_event(&Event::Key(key_event));
            }
        }

        Ok(())
    }

    pub fn render_new_rule_popup(&self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(9),
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

        //TODO: Center
        let rows = [Row::new(vec![
            Cell::from("Packet Counter".to_string())
                .bg(Color::DarkGray)
                .fg(Color::White),
            Cell::from(self.user_input.value())
                .bg(Color::DarkGray)
                .fg(Color::White),
        ])];

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
            .highlight_spacing(HighlightSpacing::Always)
            .block(
                Block::default()
                    .title(" Metrics Explorer ")
                    .bold()
                    .title_alignment(ratatui::layout::Alignment::Center)
                    .borders(Borders::all())
                    .border_type(ratatui::widgets::BorderType::Thick)
                    .border_style(Style::default().green())
                    .padding(Padding::uniform(1)),
            );

        frame.render_widget(Clear, block);
        frame.render_widget(table, block);
    }
}
