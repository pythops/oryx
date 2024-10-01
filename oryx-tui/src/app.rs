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
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EditingBlock {
    Fuzzy,
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
    pub editing_block: Option<EditingBlock>,
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
            filter: Filter::new(),
            start_sniffing: false,
            packets: packets.clone(),
            notifications: Vec::new(),
            section: Section::new(packets.clone()),
            data_channel_sender: sender,
            editing_block: None,
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
                    .constraints([Constraint::Length(8), Constraint::Fill(1)])
                    .split(frame.area());
                (chunks[0], chunks[1])
            };

            self.section.render(
                frame,
                section_block,
                &self.filter.interface.selected_interface.name,
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
        self.running = false;
    }
}
