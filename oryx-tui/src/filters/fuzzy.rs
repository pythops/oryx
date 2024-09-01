use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Cell, TableState},
};
use tui_input::Input;

use oryx_common::IpPacket;

#[derive(Debug, Default)]
pub struct Fuzzy {
    enabled: bool,
    paused: bool,
    pub filter: Input,
    pub packets: Vec<IpPacket>,
    pub scroll_state: TableState,
    pub packet_end_index: usize,
}

impl Fuzzy {
    pub fn find(&mut self, packets: &[IpPacket]) {
        self.packets = packets
            .iter()
            .copied()
            .filter(|p| p.to_string().contains(self.filter.value()))
            .collect::<Vec<IpPacket>>();
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
