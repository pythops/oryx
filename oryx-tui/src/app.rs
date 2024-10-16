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

use crate::{filter::Filter, help::Help};
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
    pub packets: Arc<Mutex<Vec<NetworkPacket>>>,
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
        let net_packets: Arc<Mutex<Vec<NetworkPacket>>> = Arc::new(Mutex::new(Vec::with_capacity(
            NetworkPacket::LEN * 1024 * 1024,
        )));
        let data_channels = Channels::new();

        thread::spawn({
            let net_packets = net_packets.clone();
            move || loop {
                if let Ok(raw_packet) = data_channels.receiver.recv() {
                    let network_packet = NetworkPacket::from(raw_packet);
                    let mut net_packets = net_packets.lock().unwrap();
                    if net_packets.len() == net_packets.capacity() {
                        net_packets.reserve(1024 * 1024);
                    }

                    net_packets.push(network_packet);
                }
            }
        });

        let firewall_channels = IoChannels::new();

        Self {
            running: true,
            help: Help::new(),
            filter: Filter::new(firewall_channels.clone()),
            start_sniffing: false,
            packets: net_packets.clone(),
            notifications: Vec::new(),
            section: Section::new(net_packets.clone(), firewall_channels.clone()),
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
