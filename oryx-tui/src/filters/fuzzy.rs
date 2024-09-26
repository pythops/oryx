use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Cell, TableState},
};
use tui_input::Input;

use crate::{app::TICK_RATE, packets::packet::AppPacket};

#[derive(Debug, Clone, Default)]
pub struct Fuzzy {
    enabled: bool,
    paused: bool,
    pub filter: Input,
    pub packets: Vec<AppPacket>,
    pub scroll_state: TableState,
    pub packet_end_index: usize,
}

impl Fuzzy {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Arc<Mutex<Self>> {
        let fuzzy = Arc::new(Mutex::new(Self::default()));

        thread::spawn({
            let fuzzy = fuzzy.clone();
            let packets = packets.clone();
            move || {
                let mut last_index = 0;
                let mut pattern = String::new();
                loop {
                    thread::sleep(Duration::from_millis(TICK_RATE));
                    let packets = packets.lock().unwrap();
                    let mut fuzzy = fuzzy.lock().unwrap();

                    if fuzzy.is_enabled() && !fuzzy.filter.value().is_empty() {
                        let current_pattern = fuzzy.filter.value().to_owned();
                        if current_pattern != pattern {
                            fuzzy.find(packets.as_slice());
                            pattern = current_pattern;
                            last_index = packets.len();
                        } else {
                            fuzzy.append(&packets.as_slice()[last_index..]);
                            last_index = packets.len();
                        }
                    }
                }
            }
        });

        fuzzy
    }

    pub fn find(&mut self, packets: &[AppPacket]) {
        self.packets = packets
            .iter()
            .copied()
            .filter(|p| p.to_string().contains(self.filter.value()))
            .collect::<Vec<AppPacket>>();
    }

    pub fn append(&mut self, packets: &[AppPacket]) {
        self.packets.append(
            &mut packets
                .iter()
                .copied()
                .filter(|p| p.to_string().contains(self.filter.value()))
                .collect::<Vec<AppPacket>>(),
        );
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        *self = Self::default();
    }

    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn unpause(&mut self) {
        self.paused = false;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }
}

pub fn highlight(pattern: &str, input: String) -> Cell {
    if !pattern.is_empty() {
        if input.contains(pattern) {
            let splits = input.split(pattern);

            let chunks = splits.into_iter().map(|c| Span::from(c.to_owned()));

            let pattern = Span::styled(pattern.to_string(), Style::new().red().bold());

            let v: Vec<Span> = itertools::intersperse(chunks, pattern).collect();

            Cell::from(Line::from(v).centered())
        } else {
            Cell::from(Line::from(input).centered())
        }
    } else {
        Cell::from(Line::from(input).centered())
    }
}
