use oryx_common::RawPacket;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};
use std::{
    error,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::{
    filter::Filter,
    help::Help,
    packet::{
        network::{IpPacket, IpProto},
        AppPacket,
    },
    pid::{self, ConnectionsInfo, IpMap},
};
use crate::{filter::IoChannels, notification::Notification};
use crate::{packet::NetworkPacket, section::Section};

pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

pub const TICK_RATE: u64 = 40;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ActivePopup {
    Help,
    UpdateFilters,
    PacketInfos,
    NewFirewallRule,
}

#[derive(Debug)]
pub struct DataEventHandler {
    pub sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub handler: thread::JoinHandle<()>,
}
#[derive(Debug, Clone)]
pub struct Channels<T> {
    pub sender: kanal::Sender<T>,
    pub receiver: kanal::Receiver<T>,
}
impl<T> Channels<T> {
    pub fn new() -> Self {
        let (sender, receiver) = kanal::unbounded();
        Self { sender, receiver }
    }
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub help: Help,
    pub filter: Filter,
    pub start_sniffing: bool,
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub connections_info: ConnectionsInfo,
    pub notifications: Vec<Notification>,
    pub section: Section,
    pub data_channel_sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub is_editing: bool,
    pub active_popup: Option<ActivePopup>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let app_packets: Arc<Mutex<Vec<AppPacket>>> = Arc::new(Mutex::new(Vec::with_capacity(
            NetworkPacket::LEN * 1024 * 1024,
        )));
        let data_channels = Channels::new();

        let tcp_map: Arc<Mutex<IpMap>> = Arc::new(Mutex::new(IpMap::new()));
        let udp_map: Arc<Mutex<IpMap>> = Arc::new(Mutex::new(IpMap::new()));

        thread::spawn({
            let app_packets = app_packets.clone();
            let tcp_map = tcp_map.clone();
            let udp_map = udp_map.clone();
            move || loop {
                if let Ok(raw_packet) = data_channels.receiver.recv() {
                    let network_packet = NetworkPacket::from(raw_packet);
                    let mut app_packets = app_packets.lock().unwrap();
                    if app_packets.len() == app_packets.capacity() {
                        app_packets.reserve(1024 * 1024);
                    }
                    let mut app_packet = AppPacket {
                        packet: network_packet,
                        pid: None,
                    };
                    let pid = match &app_packet.packet {
                        NetworkPacket::Ip(IpPacket::V4(ipv4packet)) => match ipv4packet.proto {
                            IpProto::Tcp(_) => {
                                let ipmap = tcp_map.lock().unwrap().clone();
                                app_packet.try_get_pid(ipmap)
                            }

                            IpProto::Udp(_) => {
                                let ipmap = udp_map.lock().unwrap().clone();

                                app_packet.try_get_pid(ipmap)
                            }

                            _ => None,
                        },
                        _ => None,
                    };
                    app_packet.pid = pid;
                    app_packets.push(app_packet);
                }
            }
        });

        let firewall_channels = IoChannels::new();

        let udp_map: Arc<Mutex<IpMap>> = Arc::new(Mutex::new(IpMap::new()));
        let conn_info = pid::ConnectionsInfo::new(tcp_map.clone(), udp_map.clone());

        Self {
            running: true,
            help: Help::new(),
            filter: Filter::new(firewall_channels.clone()),
            connections_info: conn_info,
            start_sniffing: false,
            packets: app_packets.clone(),
            notifications: Vec::new(),
            section: Section::new(
                app_packets.clone(),
                tcp_map.clone(),
                udp_map.clone(),
                firewall_channels.clone(),
            ),
            data_channel_sender: data_channels.sender,
            is_editing: false,
            active_popup: None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        // Setup
        if !self.start_sniffing {
            self.filter.render_on_setup(frame);
        } else {
            // Sniffing
            let (settings_block, section_block) = {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(6),
                        Constraint::Length(1),
                        Constraint::Fill(1),
                    ])
                    .split(frame.area());
                (chunks[0], chunks[2])
            };

            self.section.render(
                frame,
                section_block,
                &self.filter.interface.selected_interface.name,
                self.active_popup.as_ref(),
            );

            self.filter.render_on_sniffing(frame, settings_block);
        }
    }

    pub fn tick(&mut self) {
        self.notifications.iter_mut().for_each(|n| n.ttl -= 1);
        self.notifications.retain(|n| n.ttl > 0);
        self.section.alert.check();
    }

    pub fn quit(&mut self) {
        self.filter.terminate();
        thread::sleep(Duration::from_millis(110));
        self.running = false;
    }
}
