mod threat;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Span, Text},
    widgets::WidgetRef,
};
use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use crate::{
    packet::{
        NetworkPacket,
        direction::TrafficDirection,
        network::{IpPacket, ip::IpProto},
    },
    packet_store::PacketStore,
    section::alert::threat::synflood::SynFlood,
};

use rustc_hash::FxHashMap as HashMap;

use std::fmt::Debug;

pub trait Threat: Send + Sync + Debug + WidgetRef {}

const WIN_SIZE: usize = 100_000;

#[derive(Debug)]
pub struct Alert {
    pub flash_count: usize,
    pub threats: Arc<RwLock<Vec<Box<dyn Threat>>>>,
}

impl Alert {
    pub fn new(packets: PacketStore) -> Self {
        let ret_threats: Arc<RwLock<Vec<Box<dyn Threat>>>> = Arc::new(RwLock::new(Vec::new()));
        let threats = ret_threats.clone();

        thread::spawn(move || {
            let mut last_index = 0;
            let mut counting_index = 0;
            let mut count = 0usize;
            loop {
                thread::sleep(Duration::from_secs(5));
                // Phase 1: waiting for enough samples
                counting_index += packets
                    .for_each_range(last_index + counting_index.., |packet| {
                        if packet.direction == TrafficDirection::Ingress {
                            count += 1;
                        }
                        Ok(())
                    })
                    .unwrap();
                if count < WIN_SIZE {
                    continue;
                }
                // clear counters
                count = 0;
                counting_index = 0;

                // Phase 2: start statistics
                let mut nb_syn_packets = 0;
                let mut syn_flood_map: HashMap<IpAddr, usize> = HashMap::default();
                syn_flood_map.reserve(128);

                last_index += packets
                    .for_each_range(last_index.., |app_packet| {
                        if let NetworkPacket::Ip(ip_packet) = app_packet.frame.payload {
                            match ip_packet {
                                IpPacket::V4(ipv4_packet) => {
                                    if let IpProto::Tcp(tcp_packet) = ipv4_packet.proto
                                        && tcp_packet.syn == 1
                                    {
                                        nb_syn_packets += 1;
                                        if let Some(count) =
                                            syn_flood_map.get_mut(&IpAddr::V4(ipv4_packet.src_ip))
                                        {
                                            *count += 1;
                                        } else {
                                            syn_flood_map.insert(IpAddr::V4(ipv4_packet.src_ip), 1);
                                        }
                                    }
                                }
                                IpPacket::V6(ipv6_packet) => {
                                    if let IpProto::Tcp(tcp_packet) = ipv6_packet.proto
                                        && tcp_packet.syn == 1
                                    {
                                        nb_syn_packets += 1;
                                        if let Some(count) =
                                            syn_flood_map.get_mut(&IpAddr::V6(ipv6_packet.src_ip))
                                        {
                                            *count += 1;
                                        } else {
                                            syn_flood_map.insert(IpAddr::V6(ipv6_packet.src_ip), 1);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                threats.write().unwrap().clear();

                // 90% of incoming packets
                if (nb_syn_packets as f64 / WIN_SIZE as f64) > 0.95 {
                    let syn_flood = Box::new(SynFlood { map: syn_flood_map });
                    threats.write().unwrap().push(syn_flood);
                }
            }
        });

        Self {
            threats: ret_threats,
            flash_count: 1,
        }
    }

    pub fn check(&mut self) {
        if !self.threats.read().unwrap().is_empty() {
            self.flash_count += 1;
        } else {
            self.flash_count = 1;
        }
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
        let threats = self.threats.read().unwrap();
        if threats.is_empty() {
            let text_block = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Fill(1),
                    Constraint::Length(3),
                    Constraint::Fill(1),
                ])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .margin(2)
                .split(block)[1];

            let text = Text::from("No threats or attacks have been detected.")
                .bold()
                .centered();
            frame.render_widget(text, text_block);
            return;
        }

        let syn_flood_block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Fill(1)])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .margin(2)
            .split(block)[0];

        let syn_flood_block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Max(60),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .margin(2)
            .split(syn_flood_block)[1];

        // FIX: why ?
        // frame.render_widget_ref(x, syn_flood_block);
        for threat in threats.iter() {
            threat.render_ref(syn_flood_block, frame.buffer_mut());
        }
    }

    pub fn title_span(&self, is_focused: bool) -> Span<'_> {
        let threats = self.threats.read().unwrap();
        if is_focused {
            if !threats.is_empty() {
                if self.flash_count.is_multiple_of(12) {
                    Span::from("  Alert 󰐼   ").fg(Color::White).bg(Color::Red)
                } else {
                    Span::from("  Alert 󰐼   ").bg(Color::Red)
                }
            } else {
                Span::styled(
                    "  Alert 󰀦   ",
                    Style::default().bg(Color::Green).fg(Color::White).bold(),
                )
            }
        } else if !threats.is_empty() {
            if self.flash_count.is_multiple_of(12) {
                Span::from("  Alert 󰐼   ").fg(Color::White).bg(Color::Red)
            } else {
                Span::from("  Alert 󰐼   ").fg(Color::Red)
            }
        } else {
            Span::from("  Alert 󰀦   ").fg(Color::DarkGray)
        }
    }
}
