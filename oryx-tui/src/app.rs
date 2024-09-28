use oryx_common::RawPacket;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    Frame,
};
use std::{
    error,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tui_big_text::{BigText, PixelSize};

use crate::filters::{
    direction::{TrafficDirection, TrafficDirectionFilter},
    filter::Filter,
    fuzzy::{self, Fuzzy},
    link::LinkFilter,
    network::NetworkFilter,
    start_menu::StartMenuBlock,
    transport::TransportFilter,
    update_menu::UpdateFilterMenuBLock,
};

use crate::help::Help;
use crate::interface::Interface;
use crate::notification::Notification;
use crate::packets::{
    network::{IpPacket, IpProto},
    packet::AppPacket,
};

use crate::stats::Stats;
use crate::{alerts::alert::Alert, firewall::Firewall};
use crate::{bandwidth::Bandwidth, mode::Mode};
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

pub const TICK_RATE: u64 = 40;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FocusedBlock {
    StartMenuBlock(StartMenuBlock),
    UpdateFilterMenuBlock(UpdateFilterMenuBLock),
    Help,
    Main(Mode),
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
    pub focused_block: FocusedBlock,
    // used in setup to know which block to  fall into after discarding help
    pub previous_focused_block: FocusedBlock,
    pub interface: Interface,
    pub filter: Filter,
    pub start_sniffing: bool,
    pub packets: Arc<Mutex<Vec<AppPacket>>>,
    pub packets_table_state: TableState,
    pub fuzzy: Arc<Mutex<Fuzzy>>,
    pub notifications: Vec<Notification>,
    pub manuall_scroll: bool,
    pub mode: Mode,
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
    pub is_editing: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
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
            focused_block: FocusedBlock::StartMenuBlock(StartMenuBlock::Interface),
            previous_focused_block: FocusedBlock::StartMenuBlock(StartMenuBlock::Interface),
            interface: Interface::default(),
            filter: Filter::new(),
            start_sniffing: false,
            packets: packets.clone(),
            packets_table_state: TableState::default(),
            fuzzy: Fuzzy::new(packets.clone()),
            notifications: Vec::new(),
            manuall_scroll: false,
            mode: Mode::Packet,
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
            is_editing: false,
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        // Setup
        match self.focused_block {
            FocusedBlock::StartMenuBlock(b) => b.render(frame, &mut self),
            FocusedBlock::Main(mode) => self.render_main_section(frame, mode),
            _ => {
                match self.previous_focused_block {
                    FocusedBlock::StartMenuBlock(b) => b.render(frame, &mut self),
                    FocusedBlock::Main(mode) => self.render_main_section(frame, mode),
                    _ => {}
                }
                match self.focused_block {
                    FocusedBlock::UpdateFilterMenuBlock(b) => b.render(frame, self),
                    FocusedBlock::Help => self.help.render(frame),
                    _ => {}
                }
            }
        }
    }

    fn render_main_section(&mut self, frame: &mut Frame, mode: Mode) {
        // Build layout
        let (settings_block, mode_block) = {
            let chunks: std::rc::Rc<[Rect]> = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(8), Constraint::Fill(1)])
                .split(frame.area());
            (chunks[0], chunks[1])
        };
        let (filter_block, interface_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .margin(1)
                .split(settings_block);
            (chunks[0], chunks[1])
        };

        // Render settings
        // Interface
        self.interface.render_on_sniffing(frame, interface_block);
        // Filters
        self.filter.render_on_sniffing(frame, filter_block);

        // Render  mode section
        mode.render(frame, mode_block, self);
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
