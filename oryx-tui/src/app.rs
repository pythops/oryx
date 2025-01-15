use oryx_common::RawPacket;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};
use std::{
    error,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use crate::{
    filter::Filter,
    help::Help,
    packet::{direction::TrafficDirection, NetworkPacket},
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
    NewMetricExplorer,
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
    pub packets: Arc<RwLock<Vec<AppPacket>>>,
    pub notifications: Vec<Notification>,
    pub section: Section,
    pub data_channel_sender: kanal::Sender<([u8; RawPacket::LEN], TrafficDirection)>,
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
        let packets = Arc::new(RwLock::new(Vec::with_capacity(
            RawPacket::LEN * 1024 * 1024,
        )));

        let (sender, receiver) = kanal::unbounded();

        let firewall_channels = IoChannels::new();

        thread::spawn({
            let packets = packets.clone();
            move || loop {
                if let Ok((raw_packet, direction)) = receiver.recv() {
                    let network_packet = NetworkPacket::from(raw_packet);
                    let mut packets = packets.write().unwrap();
                    if packets.len() == packets.capacity() {
                        packets.reserve(1024 * 1024);
                    }
                    let app_packet = AppPacket {
                        packet: network_packet,
                        direction,
                    };
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
