use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock, atomic::AtomicBool},
    thread,
    time::Duration,
};

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Flex, Rect},
    style::{Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Row, Table},
};

use crate::packet::{
    AppPacket, NetworkPacket,
    direction::TrafficDirection,
    network::{IpPacket, ip::IpProto},
};

const WIN_SIZE: usize = 100_000;

#[derive(Debug)]
pub struct SynFlood {
    pub detected: Arc<AtomicBool>,
    pub map: Arc<RwLock<HashMap<IpAddr, usize>>>,
}

impl SynFlood {
    pub fn new(packets: Arc<RwLock<Vec<AppPacket>>>) -> Self {
        let map: Arc<RwLock<HashMap<IpAddr, usize>>> = Arc::new(RwLock::new(HashMap::new()));

        let detected = Arc::new(AtomicBool::new(false));

        thread::spawn({
            let packets = packets.clone();
            let map = map.clone();
            let detected = detected.clone();
            move || loop {
                let start_index = {
                    let packets = packets.read().unwrap();
                    let count = packets
                        .iter()
                        .filter(|packet| packet.direction == TrafficDirection::Ingress)
                        .count();

                    count.saturating_sub(1)
                };

                thread::sleep(Duration::from_secs(5));

                let app_packets = {
                    let packets = packets.read().unwrap();
                    packets.clone()
                };

                let app_packets: Vec<AppPacket> = app_packets
                    .into_iter()
                    .filter(|packet| packet.direction == TrafficDirection::Ingress)
                    .collect();

                let mut map = map.write().unwrap();
                map.clear();

                if app_packets.len() < WIN_SIZE {
                    continue;
                }

                let mut nb_syn_packets = 0;

                app_packets[start_index..app_packets.len().saturating_sub(1)]
                    .iter()
                    .for_each(|app_packet| {
                        if let NetworkPacket::Ip(ip_packet) = app_packet.frame.payload {
                            match ip_packet {
                                IpPacket::V4(ipv4_packet) => {
                                    if let IpProto::Tcp(tcp_packet) = ipv4_packet.proto
                                        && tcp_packet.syn == 1
                                    {
                                        nb_syn_packets += 1;
                                        if let Some(count) =
                                            map.get_mut(&IpAddr::V4(ipv4_packet.src_ip))
                                        {
                                            *count += 1;
                                        } else {
                                            map.insert(IpAddr::V4(ipv4_packet.src_ip), 1);
                                        }
                                    }
                                }
                                IpPacket::V6(ipv6_packet) => {
                                    if let IpProto::Tcp(tcp_packet) = ipv6_packet.proto
                                        && tcp_packet.syn == 1
                                    {
                                        nb_syn_packets += 1;
                                        if let Some(count) =
                                            map.get_mut(&IpAddr::V6(ipv6_packet.src_ip))
                                        {
                                            *count += 1;
                                        } else {
                                            map.insert(IpAddr::V6(ipv6_packet.src_ip), 1);
                                        }
                                    }
                                }
                            }
                        }
                    });

                // 90% of incoming packets
                if (nb_syn_packets as f64 / WIN_SIZE as f64) > 0.95 {
                    detected.store(true, std::sync::atomic::Ordering::Relaxed);
                } else {
                    detected.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });

        Self { map, detected }
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
        let mut ips: Vec<(IpAddr, usize)> = {
            let map = self.map.read().unwrap();
            map.clone().into_iter().collect()
        };
        ips.sort_by(|a, b| b.1.cmp(&a.1));

        ips.retain(|(_, count)| *count > 10_000);

        let top_3_ips = ips.into_iter().take(3);

        let widths = [Constraint::Min(30), Constraint::Min(20)];

        let rows = top_3_ips.map(|(ip, count)| {
            Row::new(vec![
                Line::from(ip.to_string()).centered().bold(),
                Line::from(count.to_string()).centered(),
            ])
        });
        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .header(
                Row::new(vec![
                    Line::from("IP Address").centered(),
                    Line::from("Number of SYN packets").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .block(
                Block::new()
                    .title(" SYN Flood Attack ")
                    .borders(Borders::all())
                    .border_style(Style::new().yellow())
                    .title_alignment(Alignment::Center),
            );

        frame.render_widget(table, block);
    }
}
