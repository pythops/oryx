use log::error;
use oryx_common::RawPacket;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};
use std::{
    error,
    sync::{Arc, Mutex},
    thread,
};

use crate::notification::Notification;
use crate::{filter::Filter, help::Help};
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
        let packets = Arc::new(Mutex::new(Vec::with_capacity(AppPacket::LEN * 1024 * 1024)));

        let (sender, receiver) = kanal::unbounded();

        let (firewall_ingress_sender, firewall_ingress_receiver) = kanal::unbounded();
        let (firewall_egress_sender, firewall_egress_receiver) = kanal::unbounded();

        thread::spawn({
            let packets = packets.clone();
            move || loop {
                if let Ok(raw_packet) = receiver.recv() {
                    let app_packet = AppPacket::from(raw_packet);
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
            filter: Filter::new(
                firewall_ingress_sender.clone(),
                firewall_ingress_receiver,
                firewall_egress_sender.clone(),
                firewall_egress_receiver,
            ),
            start_sniffing: false,
            packets: packets.clone(),
            notifications: Vec::new(),
            section: Section::new(
                packets.clone(),
                firewall_ingress_sender,
                firewall_egress_sender,
            ),
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
        match self.section.firewall.save_rules() {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err)
            }
        }
        self.running = false;
    }
}
