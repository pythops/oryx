use std::{
    sync::{Arc, Mutex, RwLock},
    thread,
    time::Duration,
};

use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Cell, TableState},
};
use tui_input::Input;

use crate::{app::TICK_RATE, packet::AppPacket};

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
    pub fn new(packets: Arc<RwLock<Vec<AppPacket>>>) -> Arc<Mutex<Self>> {
        let fuzzy = Arc::new(Mutex::new(Self::default()));

        thread::spawn({
            let fuzzy = fuzzy.clone();
            let packets = packets.clone();
            move || {
                let mut last_index = 0;
                let mut pattern = String::new();
                loop {
                    thread::sleep(Duration::from_millis(TICK_RATE));
                    let mut fuzzy = fuzzy.lock().unwrap();

                    if fuzzy.is_enabled() && !fuzzy.filter.value().is_empty() {
                        let packets = packets.read().unwrap();
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

    pub fn scroll_down(&mut self, win_size: usize) {
        let i = match self.scroll_state.selected() {
            Some(i) => {
                if i < win_size - 1 {
                    i + 1
                } else if i == win_size - 1 && self.packets.len() > self.packet_end_index {
                    // shit the window by one
                    self.packet_end_index += 1;
                    i + 1
                } else {
                    i
                }
            }
            None => self.packets.len(),
        };

        self.scroll_state.select(Some(i));
    }

    pub fn scroll_up(&mut self, win_size: usize) {
        let i = match self.scroll_state.selected() {
            Some(i) => {
                if i > 1 {
                    i - 1
                } else if i == 0 && self.packet_end_index > win_size {
                    // shit the window by one
                    self.packet_end_index -= 1;
                    0
                } else {
                    0
                }
            }
            None => self.packets.len(),
        };

        self.scroll_state.select(Some(i));
    }

    pub fn find(&mut self, packets: &[AppPacket]) {
        self.packets = packets
            .iter()
            .copied()
            .filter(|p| {
                p.frame.payload.to_string().contains(self.filter.value())
                    | p.pid
                        .is_some_and(|v| v.to_string().contains(self.filter.value()))
            })
            .collect::<Vec<AppPacket>>();
    }

    pub fn append(&mut self, packets: &[AppPacket]) {
        self.packets.append(
            &mut packets
                .iter()
                .copied()
                .filter(|p| {
                    p.frame.payload.to_string().contains(self.filter.value())
                        | p.pid
                            .is_some_and(|v| v.to_string().contains(self.filter.value()))
                })
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

pub fn highlight(pattern: &str, input: String) -> Cell<'_> {
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
