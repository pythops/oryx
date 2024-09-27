use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding},
    Frame,
};
#[derive(Debug, PartialEq)]
pub enum Mode {
    Packet,
    Stats,
    Alerts,
    Firewall,
}

impl Mode {
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
}
