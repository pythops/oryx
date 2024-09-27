use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding},
    Frame,
};

use crate::app::App;
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Packet,
    Stats,
    Alerts,
    Firewall,
}

impl Mode {
    pub fn next(&mut self) {
        *self = match self {
            Mode::Packet => Mode::Stats,
            Mode::Stats => Mode::Alerts,
            Mode::Alerts => Mode::Firewall,
            Mode::Firewall => Mode::Packet,
        }
    }
    pub fn previous(&mut self) {
        *self = match self {
            Mode::Packet => Mode::Firewall,
            Mode::Stats => Mode::Packet,
            Mode::Alerts => Mode::Stats,
            Mode::Firewall => Mode::Alerts,
        };
    }
    pub fn render(&self, frame: &mut Frame, area: Rect, alert_span: Span<'_>) {
        let header = match self {
            Self::Packet => {
                vec![
                    Span::styled(
                        " Packet ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span,
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Stats => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::styled(
                        " Stats ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                    alert_span,
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Alerts => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span.bold(),
                    Span::from(" Firewall ").fg(Color::DarkGray),
                ]
            }

            Self::Firewall => {
                vec![
                    Span::from(" Packet ").fg(Color::DarkGray),
                    Span::from(" Stats ").fg(Color::DarkGray),
                    alert_span,
                    Span::styled(
                        " Firewall ",
                        Style::default().bg(Color::Green).fg(Color::White).bold(),
                    ),
                ]
            }
        };

        frame.render_widget(
            Block::default()
                .title(Line::from(header))
                .title_alignment(Alignment::Left)
                .padding(Padding::top(2))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
            area,
        );
    }

    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Tab => {
                self.next();
            }
            KeyCode::BackTab => {
                self.previous();
            }

            _ => {
                let fuzzy = app.fuzzy.clone();
                let mut fuzzy = fuzzy.lock().unwrap();
                if fuzzy.is_enabled() {
                    match key_event.code {
                        KeyCode::Esc => {
                            if fuzzy.is_paused() {
                                if app.manuall_scroll {
                                    app.manuall_scroll = false;
                                } else {
                                    fuzzy.disable();
                                }
                            } else {
                                fuzzy.pause();
                            }
                        }
                        _ => {
                            if !fuzzy.is_paused() && !app.update_filters {
                                fuzzy
                                    .filter
                                    .handle_event(&crossterm::event::Event::Key(key_event));
                            }
                        }
                    }
                } else {
                    match self {
                        Mode::Packet => match key_event.code {
                            KeyCode::Char('i') => {
                                if !app.packet_index.is_none() && !fuzzy.packets.is_empty() {
                                    app.show_packet_infos_popup = true;
                                }
                            }
                            KeyCode::Char('/') => {
                                fuzzy.enable();
                                fuzzy.unpause();
                            }
                            KeyCode::Char('j') | KeyCode::Down => {
                                if !app.manuall_scroll {
                                    app.manuall_scroll = true;
                                    // Record the last position. Usefull for selecting the packets to display
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                    let i = match fuzzy.scroll_state.selected() {
                                        Some(i) => {
                                            if i < app.packet_window_size - 1 {
                                                i + 1
                                            } else if i == app.packet_window_size - 1
                                                && fuzzy.packets.len() > fuzzy.packet_end_index
                                            {
                                                // shit the window by one
                                                fuzzy.packet_end_index += 1;
                                                i + 1
                                            } else {
                                                i
                                            }
                                        }
                                        None => fuzzy.packets.len(),
                                    };

                                    fuzzy.scroll_state.select(Some(i));
                                }
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                if !app.manuall_scroll {
                                    app.manuall_scroll = true;
                                    // Record the last position. Usefull for selecting the packets to display
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                }
                                let i = match fuzzy.scroll_state.selected() {
                                    Some(i) => {
                                        if i > 1 {
                                            i - 1
                                        } else if i == 0
                                            && fuzzy.packet_end_index > app.packet_window_size
                                        {
                                            // shit the window by one
                                            fuzzy.packet_end_index -= 1;
                                            0
                                        } else {
                                            0
                                        }
                                    }
                                    None => fuzzy.packets.len(),
                                };

                                fuzzy.scroll_state.select(Some(i));
                            }

                            _ => {}
                        },
                        Mode::Firewall => match key_event.code {
                            KeyCode::Char('n') => {}
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
    }
}
