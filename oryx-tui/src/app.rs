use oryx_common::RawPacket;
use ratatui::widgets::TableState;
use std::{
    error,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::{
    ebpf::Ebpf,
    event::Event,
    filters::{direction::TrafficDirection, filter::Filter, fuzzy::Fuzzy},
    phase::Phase,
    startup::Startup,
    update::UpdateBlockEnum,
};

use crate::help::Help;
use crate::interface::Interface;
use crate::notification::Notification;
use crate::packets::packet::AppPacket;

use crate::alerts::alert::Alert;
use crate::bandwidth::Bandwidth;

use crate::sections::{firewall::Firewall, section::Section, stats::Stats};
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

pub const TICK_RATE: u64 = 40;

// #[derive(Debug, Clone, PartialEq)]
// pub enum FocusedBlock {
//     StartMenuBlock(StartMenuBlock),
//     UpdateFilterMenuBlock(UpdateFilterMenuBlock),
//     Help,
//     Main(Section),
// }

#[derive(Debug)]
pub struct DataEventHandler {
    pub sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub handler: thread::JoinHandle<()>,
}

#[derive(Debug, PartialEq)]
pub enum Mode {
    Normal,
    Insert,
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub help: Help,
    // pub focused_block: FocusedBlock,
    // // used in setup to know which block to  fall into after discarding help
    // pub previous_focused_block: FocusedBlock,
    pub startup: Startup,
    pub filter_update: UpdateBlockEnum,
    pub interface: Interface,
    pub filter: Filter,
    pub phase: Phase,
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub packets_table_state: TableState,
    pub fuzzy: Arc<Mutex<Fuzzy>>,
    pub notifications: Vec<Notification>,
    pub manuall_scroll: bool,
    pub section: Section,
    pub stats: Arc<Mutex<Stats>>,
    pub packet_end_index: usize,
    pub packet_window_size: usize,
    pub update_filters: bool,
    pub data_channel_sender: kanal::Sender<[u8; RawPacket::LEN]>,
    pub bandwidth: Bandwidth,
    pub show_packet_infos_popup: bool,
    pub packet_index: Option<usize>,
    pub alert: Alert,
    pub firewall: Firewall,
    pub mode: Mode,
    pub notification_sender: kanal::Sender<Event>,
}

impl App {
    pub fn new(notification_sender: kanal::Sender<Event>) -> Self {
        let packets = Arc::new(Mutex::new(Vec::with_capacity(AppPacket::LEN * 1024 * 1024)));
        let stats = Arc::new(Mutex::new(Stats::default()));

        let (sender, receiver) = kanal::unbounded();

        thread::spawn({
            let packets = packets.clone();
            let stats = stats.clone();

            move || loop {
                if let Ok(raw_packet) = receiver.recv() {
                    App::process(packets.clone(), stats.clone(), AppPacket::from(raw_packet));
                }
            }
        });

        Self {
            running: true,
            help: Help::new(),
            startup: Startup::new(),
            // focused_block: FocusedBlock::StartMenuBlock(StartMenuBlock::Interface),
            // previous_focused_block: FocusedBlock::StartMenuBlock(StartMenuBlock::Interface),
            interface: Interface::default(),
            filter: Filter::new(),
            phase: Phase::new(),
            filter_update: UpdateBlockEnum::NetworkFilter,
            packets: packets.clone(),
            packets_table_state: TableState::default(),
            fuzzy: Fuzzy::new(packets.clone()),
            notifications: Vec::new(),
            manuall_scroll: false,
            section: Section::Packet,
            stats,
            packet_end_index: 0,
            packet_window_size: 0,
            update_filters: false,
            data_channel_sender: sender,
            bandwidth: Bandwidth::new(),
            show_packet_infos_popup: false,
            packet_index: None,
            alert: Alert::new(packets.clone()),
            firewall: Firewall::new(),
            mode: Mode::Normal,
            notification_sender,
        }
    }

    pub fn load_ingress(&self) {
        {
            Ebpf::load_ingress(
                self.interface.selected_interface.name.clone(),
                self.notification_sender.clone(),
                self.data_channel_sender.clone(),
                self.filter.ingress_channel.receiver.clone(),
                self.filter.traffic_direction.terminate_ingress.clone(),
            );
        }
    }
    pub fn load_egress(&self) {
        {
            Ebpf::load_egress(
                self.interface.selected_interface.name.clone(),
                self.notification_sender.clone(),
                self.data_channel_sender.clone(),
                self.filter.egress_channel.receiver.clone(),
                self.filter.traffic_direction.terminate_egress.clone(),
            );
        }
    }

    pub fn detach_ebpf(&mut self) {
        self.filter
            .traffic_direction
            .terminate(TrafficDirection::Egress);
        self.filter
            .traffic_direction
            .terminate(TrafficDirection::Ingress);
        thread::sleep(Duration::from_millis(150));
    }

    pub fn process(
        packets: Arc<Mutex<Vec<AppPacket>>>,
        stats: Arc<Mutex<Stats>>,
        app_packet: AppPacket,
    ) {
        let mut packets = packets.lock().unwrap();

        if packets.len() == packets.capacity() {
            packets.reserve(1024 * 1024);
        }

        packets.push(app_packet);

        let mut stats = stats.lock().unwrap();
        stats.refresh(&app_packet);
    }

    pub fn tick(&mut self) {
        self.notifications.iter_mut().for_each(|n| n.ttl -= 1);
        self.notifications.retain(|n| n.ttl > 0);

        self.alert.check();
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}
