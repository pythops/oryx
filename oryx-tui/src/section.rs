pub mod alert;
pub mod firewall;
pub mod inspection;
pub mod metrics;
pub mod stats;

use std::sync::{Arc, RwLock};

use alert::Alert;
use crossterm::event::{KeyCode, KeyEvent};
use firewall::{Firewall, FirewallSignal};

use inspection::Inspection;
use metrics::Metrics;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Padding},
};
use stats::Stats;

use crate::{
    app::{ActivePopup, AppResult},
    event::Event,
    filter::IoChannels,
    packet::AppPacket,
};

#[derive(Debug, PartialEq)]
pub enum FocusedSection {
    Inspection,
    Stats,
    Metrics,
    Alerts,
    Firewall,
}

#[derive(Debug)]
pub struct Section {
    pub focused_section: FocusedSection,
    pub inspection: Inspection,
    pub stats: Option<Stats>,
    pub metrics: Metrics,
    pub alert: Alert,
    pub firewall: Firewall,
}

impl Section {
    pub fn new(
        packets: Arc<RwLock<Vec<AppPacket>>>,
        firewall_chans: IoChannels<FirewallSignal>,
    ) -> Self {
        Self {
            focused_section: FocusedSection::Inspection,
            inspection: Inspection::new(packets.clone()),
            stats: None,
            metrics: Metrics::new(packets.clone()),
            alert: Alert::new(packets.clone()),
            firewall: Firewall::new(firewall_chans.ingress.sender, firewall_chans.egress.sender),
        }
    }
    fn title_span(&self, header_section: FocusedSection) -> Span<'_> {
        let is_focused = self.focused_section == header_section;
        match header_section {
            FocusedSection::Inspection => {
                if is_focused {
                    Span::styled(
                        "  Inspection 󰏖   ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from("  Inspection 󰏖   ").fg(Color::DarkGray)
                }
            }
            FocusedSection::Stats => {
                if is_focused {
                    Span::styled(
                        "  Stats 󱕍   ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from("  Stats 󱕍   ").fg(Color::DarkGray)
                }
            }
            FocusedSection::Metrics => {
                if is_focused {
                    Span::styled(
                        "  Metrics    ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from("  Metrics    ").fg(Color::DarkGray)
                }
            }
            FocusedSection::Alerts => self.alert.title_span(is_focused),
            FocusedSection::Firewall => {
                if is_focused {
                    Span::styled(
                        "  Firewall 󰞀   ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    )
                } else {
                    Span::from("  Firewall 󰞀   ").fg(Color::DarkGray)
                }
            }
        }
    }

    fn render_footer_help(
        &self,
        frame: &mut Frame,
        block: Rect,
        active_popup: Option<&ActivePopup>,
    ) {
        let message = {
            match active_popup {
                Some(ActivePopup::UpdateFilters) => Line::from(vec![
                    Span::from("k,").bold(),
                    Span::from("  Up"),
                    Span::from(" | "),
                    Span::from("j,").bold(),
                    Span::from("  Down"),
                    Span::from(" | "),
                    Span::from("󱁐").bold(),
                    Span::from(" Toggle Select"),
                    Span::from(" | "),
                    Span::from("󱊷 ").bold(),
                    Span::from(": Discard"),
                    Span::from(" | "),
                    Span::from("↲").bold(),
                    Span::from(" Apply"),
                    Span::from(" | "),
                    Span::from("⇄").bold(),
                    Span::from(" Nav"),
                ]),
                Some(ActivePopup::NewFirewallRule) => Line::from(vec![
                    Span::from("j,k,,").bold(),
                    Span::from(" Toggle Direction"),
                    Span::from(" | "),
                    Span::from("󱊷 ").bold(),
                    Span::from(" Discard"),
                    Span::from(" | "),
                    Span::from("↲").bold(),
                    Span::from(" Save"),
                    Span::from(" | "),
                    Span::from("⇄").bold(),
                    Span::from(" Naviguate"),
                ]),
                Some(ActivePopup::NewMetricExplorer) => Line::from(vec![
                    Span::from("󱊷 ").bold(),
                    Span::from(" Discard"),
                    Span::from(" | "),
                    Span::from("↲").bold(),
                    Span::from(" Run"),
                ]),
                Some(ActivePopup::PacketInfos) | Some(ActivePopup::Help) => Line::from(vec![
                    Span::from("󱊷 ").bold(),
                    Span::from(" Discard Popup").bold(),
                ]),
                _ => match self.focused_section {
                    FocusedSection::Inspection => Line::from(vec![
                        Span::from("k,").bold(),
                        Span::from("  Up"),
                        Span::from(" | "),
                        Span::from("j,").bold(),
                        Span::from("  Down"),
                        Span::from(" | "),
                        Span::from("/").bold(),
                        Span::from(" Search"),
                        Span::from(" | "),
                        Span::from("i").bold(),
                        Span::from(" Infos"),
                        Span::from(" | "),
                        Span::from("s").bold(),
                        Span::from(" Save"),
                        Span::from(" | "),
                        Span::from("f").bold(),
                        Span::from(" Filters"),
                        Span::from(" | "),
                        Span::from("󱊷 ").bold(),
                        Span::from(" Discard"),
                        Span::from(" | "),
                        Span::from("⇄").bold(),
                        Span::from(" Nav"),
                    ]),
                    FocusedSection::Firewall => Line::from(vec![
                        Span::from("k,").bold(),
                        Span::from("  Up"),
                        Span::from(" | "),
                        Span::from("j,").bold(),
                        Span::from("  Down"),
                        Span::from(" | "),
                        Span::from("n").bold(),
                        Span::from(" New"),
                        Span::from(" | "),
                        Span::from("d").bold(),
                        Span::from(" Delete"),
                        Span::from(" | "),
                        Span::from("e").bold(),
                        Span::from(" Edit"),
                        Span::from(" | "),
                        Span::from("s").bold(),
                        Span::from(" Save"),
                        Span::from(" | "),
                        Span::from("󱁐 ").bold(),
                        Span::from(" Toggle"),
                        Span::from(" | "),
                        Span::from("f").bold(),
                        Span::from(" Filters"),
                        Span::from(" | "),
                        Span::from("⇄").bold(),
                        Span::from(" Nav"),
                    ]),
                    FocusedSection::Metrics => Line::from(vec![
                        Span::from("k,").bold(),
                        Span::from("  Up"),
                        Span::from(" | "),
                        Span::from("j,").bold(),
                        Span::from("  Down"),
                        Span::from(" | "),
                        Span::from("n").bold(),
                        Span::from(" New"),
                        Span::from(" | "),
                        Span::from("d").bold(),
                        Span::from(" Delete"),
                        Span::from(" | "),
                        Span::from("f").bold(),
                        Span::from(" Filters"),
                        Span::from(" | "),
                        Span::from("⇄").bold(),
                        Span::from(" Nav"),
                    ]),
                    _ => Line::from(vec![
                        Span::from("f").bold(),
                        Span::from(" Filters"),
                        Span::from(" | "),
                        Span::from("⇄").bold(),
                        Span::from(" Nav"),
                    ]),
                },
            }
        };

        let help = Text::from(vec![Line::from(""), message]).blue().centered();
        frame.render_widget(
            help,
            block.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );
    }

    pub fn render_header(&mut self, frame: &mut Frame, block: Rect) {
        frame.render_widget(
            Block::default()
                .title({
                    Line::from(vec![
                        self.title_span(FocusedSection::Inspection),
                        self.title_span(FocusedSection::Stats),
                        self.title_span(FocusedSection::Metrics),
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

    pub fn render(
        &mut self,
        frame: &mut Frame,
        block: Rect,
        network_interface: &str,
        active_popup: Option<&ActivePopup>,
    ) {
        let (section_block, help_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Fill(1), Constraint::Length(3)])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .split(block);

            (chunks[0], chunks[1])
        };

        self.render_header(frame, section_block);
        self.render_footer_help(frame, help_block, active_popup);

        match self.focused_section {
            FocusedSection::Inspection => self.inspection.render(frame, section_block),
            FocusedSection::Stats => {
                if let Some(stats) = &self.stats {
                    stats.render(frame, section_block, network_interface)
                }
            }
            FocusedSection::Metrics => self.metrics.render(frame, section_block),
            FocusedSection::Alerts => self.alert.render(frame, section_block),
            FocusedSection::Firewall => self.firewall.render(frame, section_block),
        }
    }

    pub fn handle_keys(
        &mut self,
        key_event: KeyEvent,
        notification_sender: kanal::Sender<Event>,
    ) -> AppResult<()> {
        match key_event.code {
            KeyCode::Tab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Stats,
                FocusedSection::Stats => self.focused_section = FocusedSection::Metrics,
                FocusedSection::Metrics => self.focused_section = FocusedSection::Alerts,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Firewall,
                FocusedSection::Firewall => self.focused_section = FocusedSection::Inspection,
            },

            KeyCode::BackTab => match self.focused_section {
                FocusedSection::Inspection => self.focused_section = FocusedSection::Firewall,
                FocusedSection::Stats => self.focused_section = FocusedSection::Inspection,
                FocusedSection::Metrics => self.focused_section = FocusedSection::Stats,
                FocusedSection::Alerts => self.focused_section = FocusedSection::Metrics,
                FocusedSection::Firewall => self.focused_section = FocusedSection::Alerts,
            },

            _ => match self.focused_section {
                FocusedSection::Inspection => self
                    .inspection
                    .handle_keys(key_event, notification_sender.clone())?,
                FocusedSection::Firewall => self
                    .firewall
                    .handle_keys(key_event, notification_sender.clone())?,
                FocusedSection::Metrics => self.metrics.handle_keys(key_event),
                _ => {}
            },
        }
        Ok(())
    }
}
