pub mod alert;
pub mod inspection;
pub mod stats;

use std::sync::{Arc, Mutex};

use alert::Alert;
use crossterm::event::{KeyCode, KeyEvent};

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
}

#[derive(Debug)]
pub struct Section {
    focused_section: FocusedSection,
    pub inspection: Inspection,
    pub stats: Stats,
    pub alert: Alert,
}

impl Section {
    pub fn new(packets: Arc<Mutex<Vec<AppPacket>>>) -> Self {
        Self {
            focused_section: FocusedSection::Inspection,
            inspection: Inspection::new(packets.clone()),
            stats: Stats::new(packets.clone()),
            alert: Alert::new(packets.clone()),
        }
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect, network_interace: &str) {
        match self.focused_section {
            FocusedSection::Inspection => {
                frame.render_widget(
                    Block::default()
                        .title({
                            Line::from(vec![
                                Span::styled(
                                    " Inspection ",
                                    Style::default().bg(Color::Green).fg(Color::White).bold(),
                                ),
                                Span::from(" Stats ").fg(Color::DarkGray),
                                self.alert.title_span(false),
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
                self.inspection.render(frame, block);
            }
            FocusedSection::Stats => {
                frame.render_widget(
                    Block::default()
                        .title({
                            Line::from(vec![
                                Span::from(" Inspection ").fg(Color::DarkGray),
                                Span::styled(
                                    " Stats ",
                                    Style::default().bg(Color::Green).fg(Color::White).bold(),
                                ),
                                self.alert.title_span(false),
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
                self.stats.render(frame, block, network_interace)
            }
            FocusedSection::Alerts => {
                frame.render_widget(
                    Block::default()
                        .title({
                            Line::from(vec![
                                Span::from(" Inspection ").fg(Color::DarkGray),
                                Span::from(" Stats ").fg(Color::DarkGray),
                                self.alert.title_span(true),
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

                self.alert.render(frame, block);
            }
        }
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Tab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Stats,
                FocusedSection::Stats => self.focused_section = FocusedSection::Alerts,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Inspection,
            },

            KeyCode::BackTab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Alerts,
                FocusedSection::Stats => self.focused_section = FocusedSection::Inspection,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Stats,
            },

            _ => {
                if self.focused_section == FocusedSection::Inspection {
                    self.inspection.handle_keys(key_event);
                }
            }
        }
    }
}
