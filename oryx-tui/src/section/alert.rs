mod syn_flood;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Span, Text},
    Frame,
};
use std::sync::{atomic::Ordering, Arc, Mutex};
use syn_flood::SynFlood;

use crate::packet::AppPacket;

#[derive(Debug)]
pub struct Alert {
    syn_flood: SynFlood,
    pub flash_count: usize,
    pub detected: bool,
}

impl Alert {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Self {
        Self {
            syn_flood: SynFlood::new(packets),
            flash_count: 1,
            detected: false,
        }
    }

    pub fn check(&mut self) {
        if self.syn_flood.detected.load(Ordering::Relaxed) {
            self.detected = true;
            self.flash_count += 1;
        } else {
            self.detected = false;
            self.flash_count = 1;
        }
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
        if !self.detected {
            let text_block = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Fill(1),
                    Constraint::Length(3),
                    Constraint::Fill(1),
                ])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .margin(2)
                .split(block)[1];

            let text = Text::from("No alerts").bold().centered();
            frame.render_widget(text, text_block);
            return;
        }

        let syn_flood_block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Fill(1)])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .margin(2)
            .split(block)[0];

        let syn_flood_block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Max(60),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .margin(2)
            .split(syn_flood_block)[1];

        self.syn_flood.render(frame, syn_flood_block);
    }

    pub fn title_span(&self, is_focused: bool) -> Span<'_> {
        if is_focused {
            if self.detected {
                if self.flash_count % 12 == 0 {
                    Span::from("  Alert 󰐼   ").fg(Color::White).bg(Color::Red)
                } else {
                    Span::from("  Alert 󰐼   ").bg(Color::Red)
                }
            } else {
                Span::styled(
                    "  Alert 󰀦   ",
                    Style::default().bg(Color::Green).fg(Color::White).bold(),
                )
            }
        } else if self.detected {
            if self.flash_count % 12 == 0 {
                Span::from("  Alert 󰐼   ").fg(Color::White).bg(Color::Red)
            } else {
                Span::from("  Alert 󰐼   ").fg(Color::Red)
            }
        } else {
            Span::from("  Alert 󰀦   ").fg(Color::DarkGray)
        }
    }
}
