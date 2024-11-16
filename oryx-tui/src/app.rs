use oryx_common::RawPacket;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};
use std::{
    error,
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
    time::Duration,
};

use crate::{
    filter::Filter,
    help::Help,
    packet::{direction::TrafficDirection, NetworkPacket},
    pid::{self, ConnectionMap},
};

use crate::{filter::IoChannels, notification::Notification};
use crate::{packet::AppPacket, section::Section};

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

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub help: Help,
    pub filter: Filter,
    pub start_sniffing: bool,
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub notifications: Vec<Notification>,
    pub section: Section,
    pub data_channel_sender: kanal::Sender<([u8; RawPacket::LEN], TrafficDirection)>,
    pub is_editing: bool,
    pub active_popup: Option<ActivePopup>,
    pub pid_terminate: Arc<AtomicBool>,
    pub pid_map: Arc<Mutex<ConnectionMap>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let packets = Arc::new(Mutex::new(Vec::with_capacity(RawPacket::LEN * 1024 * 1024)));
        let pid_map = Arc::new(Mutex::new(ConnectionMap::new()));

        let (sender, receiver) = kanal::unbounded();

        let firewall_channels = IoChannels::new();
        thread::spawn({
            let packets = packets.clone();
            let pid_map = pid_map.clone();
            move || loop {
                if let Ok((raw_packet, direction)) = receiver.recv() {
                    let network_packet = NetworkPacket::from(raw_packet);

                    let pid = {
                        if direction == TrafficDirection::Egress {
                            let pid_map = {
                                let map = pid_map.lock().unwrap();
                                map.clone()
                            };
                            pid::get_pid(network_packet, &pid_map)
                        } else {
                            None
                        }
                    };

                    let app_packet = AppPacket {
                        packet: network_packet,
                        pid,
                        direction,
                    };

                    let mut packets = packets.lock().unwrap();
                    if packets.len() == packets.capacity() {
                        packets.reserve(1024 * 1024);
                    }

                    packets.push(app_packet);
                }
            }
        });

        Self {
            running: true,
            help: Help::new(),
            filter: Filter::new(firewall_channels.clone()),
            start_sniffing: false,
            packets: packets.clone(),
            notifications: Vec::new(),
            section: Section::new(packets.clone(), firewall_channels.clone()),
            data_channel_sender: sender,
            is_editing: false,
            active_popup: None,
            pid_terminate: Arc::new(AtomicBool::new(false)),
            pid_map,
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
        self.pid_terminate
            .store(true, std::sync::atomic::Ordering::Relaxed);
        thread::sleep(Duration::from_millis(110));
        self.running = false;
    }
}
