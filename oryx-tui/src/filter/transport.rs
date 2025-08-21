use oryx_common::protocols::{NB_TRANSPORT_PROTOCOL, TransportProtocol};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Text,
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
};

#[derive(Debug)]
pub struct TransportFilter {
    pub state: TableState,
    pub selected_protocols: Vec<TransportProtocol>,
    pub applied_protocols: Vec<TransportProtocol>,
}

impl TransportFilter {
    pub fn new(protocols: Vec<TransportProtocol>) -> Self {
        Self {
            state: TableState::default(),
            selected_protocols: protocols,
            applied_protocols: Vec::new(),
        }
    }

    pub fn select(&mut self) {
        if let Some(i) = self.state.selected() {
            let protocol = match i {
                0 => TransportProtocol::TCP,
                1 => TransportProtocol::UDP,
                _ => TransportProtocol::SCTP,
            };

            if self.selected_protocols.contains(&protocol) {
                self.selected_protocols.retain(|&p| p != protocol);
            } else {
                self.selected_protocols.push(protocol);
            }
        }
    }

    pub fn scroll_down(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i < (NB_TRANSPORT_PROTOCOL - 1).into() {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
    }

    pub fn scroll_up(&mut self) {
        let i = match self.state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };

        self.state.select(Some(i));
    }

    pub fn apply(&mut self) {
        self.applied_protocols = self.selected_protocols.clone();
        self.selected_protocols.clear();
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect, is_focused: bool, update: bool) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Fill(1),
                    Constraint::Length(25),
                    Constraint::Length(if update { 20 } else { 55 }),
                    Constraint::Fill(1),
                ]
                .as_ref(),
            )
            .flex(Flex::Center)
            .split(block);

        // title

        let title_block = layout[1];

        let title_block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .flex(Flex::Center)
            .split(title_block)[1];

        let title = if is_focused {
            Text::from("Transport Filters 󱪤  ").bold()
        } else {
            Text::from("Transport Filters 󱪤  ")
        };
        frame.render_widget(title, title_block);

        //

        let area = layout[2];

        let widths = [Constraint::Length(2), Constraint::Fill(1)];
        let transport_filters = vec![
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&TransportProtocol::TCP) {
                        " "
                    } else {
                        ""
                    }
                },
                "TCP",
            ]),
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&TransportProtocol::UDP) {
                        " "
                    } else {
                        ""
                    }
                },
                "UDP",
            ]),
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&TransportProtocol::SCTP) {
                        " "
                    } else {
                        ""
                    }
                },
                "SCTP",
            ]),
        ];

        let table = Table::new(transport_filters, widths)
            .row_highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .borders(Borders::LEFT)
                .border_type(if is_focused {
                    BorderType::QuadrantOutside
                } else {
                    BorderType::default()
                })
                .border_style(Style::default().fg(Color::Green)),
            area,
        );

        frame.render_stateful_widget(
            table,
            area.inner(ratatui::layout::Margin {
                horizontal: 2,
                vertical: 0,
            }),
            &mut self.state,
        );
    }
}
