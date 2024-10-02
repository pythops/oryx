pub mod alert;
pub mod firewall;
pub mod inspection;
pub mod stats;

use std::sync::{Arc, Mutex};

use alert::Alert;
use crossterm::event::{KeyCode, KeyEvent};
use firewall::Firewall;

use inspection::Inspection;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding},
    Frame,
};
use stats::Stats;

use crate::packet::AppPacket;

#[derive(Debug, PartialEq)]
pub enum FocusedSection {
    Inspection,
    Stats,
    Alerts,
    Firewall,
}

#[derive(Debug)]
pub struct Section {
    focused_section: FocusedSection,
    pub inspection: Inspection,
    pub stats: Stats,
    pub alert: Alert,
    pub firewall: Firewall,
}

impl Section {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Self {
        Self {
            focused_section: FocusedSection::Inspection,
            inspection: Inspection::new(packets.clone()),
            stats: Stats::new(packets.clone()),
            alert: Alert::new(packets.clone()),
            firewall: Firewall::new(),
        }
    }
    fn title_span(&self, header_section: FocusedSection) -> Span {
        let is_focused = self.focused_section == header_section;
        match header_section {
            FocusedSection::Inspection => {
                if is_focused {
                    Span::styled(
                        " Inspection ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from(" Inspection ").fg(Color::DarkGray)
                }
            }
            FocusedSection::Stats => {
                if is_focused {
                    Span::styled(
                        " Stats ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from(" Stats ").fg(Color::DarkGray)
                }
            }
            FocusedSection::Alerts => self.alert.title_span(is_focused),
            FocusedSection::Firewall => {
                if is_focused {
                    Span::styled(
                        " Firewall ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from(" Firewall ").fg(Color::DarkGray)
                }
            }
        }
    }

    pub fn render_header(&mut self, frame: &mut Frame, block: Rect) {
        frame.render_widget(
            Block::default()
                .title({
                    Line::from(vec![
                        self.title_span(FocusedSection::Inspection),
                        self.title_span(FocusedSection::Stats),
                        self.title_span(FocusedSection::Alerts),
                        self.title_span(FocusedSection::Firewall),
                    ])
                })
                .title_alignment(Alignment::Left)
                .padding(Padding::top(1))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
            block,
        );
    }
    pub fn render(&mut self, frame: &mut Frame, block: Rect, network_interace: &str) {
        self.render_header(frame, block);
        match self.focused_section {
            FocusedSection::Inspection => self.inspection.render(frame, block),
            FocusedSection::Stats => self.stats.render(frame, block, network_interace),
            FocusedSection::Alerts => self.alert.render(frame, block),
            FocusedSection::Firewall => self.alert.render(frame, block),
        }
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Tab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Stats,
                FocusedSection::Stats => self.focused_section = FocusedSection::Alerts,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Firewall,
                FocusedSection::Firewall => self.focused_section = FocusedSection::Inspection,
            },

            KeyCode::BackTab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Firewall,
                FocusedSection::Stats => self.focused_section = FocusedSection::Inspection,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Stats,
                FocusedSection::Firewall => self.focused_section = FocusedSection::Alerts,
            },

            _ => {
                if self.focused_section == FocusedSection::Inspection {
                    self.inspection.handle_keys(key_event);
                }
            }
        }
    }
}
