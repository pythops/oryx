use oryx_common::protocols::{NB_NETWORK_PROTOCOL, NetworkProtocol};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
};

#[derive(Debug)]
pub struct NetworkFilter {
    pub state: TableState,
    pub selected_protocols: Vec<NetworkProtocol>,
    pub applied_protocols: Vec<NetworkProtocol>,
}

impl NetworkFilter {
    pub fn new(protocols: Vec<NetworkProtocol>) -> Self {
        NetworkFilter {
            state: TableState::default(),
            selected_protocols: protocols,
            applied_protocols: Vec::new(),
        }
    }

    pub fn select(&mut self) {
        if let Some(i) = self.state.selected() {
            let protocol = match i {
                0 => NetworkProtocol::Ipv4,
                1 => NetworkProtocol::Ipv6,
                _ => NetworkProtocol::Icmp,
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
                if i < (NB_NETWORK_PROTOCOL - 1).into() {
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

    pub fn render(&mut self, frame: &mut Frame, block: Rect, is_focused: bool) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Fill(1),
                    Constraint::Length(55),
                    Constraint::Fill(1),
                ]
                .as_ref(),
            )
            .flex(Flex::Center)
            .split(block);

        let area = layout[1];

        let widths = [Constraint::Length(2), Constraint::Fill(1)];
        let network_filters = vec![
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&NetworkProtocol::Ipv4) {
                        " "
                    } else {
                        ""
                    }
                },
                "IPv4",
            ]),
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&NetworkProtocol::Ipv6) {
                        " "
                    } else {
                        ""
                    }
                },
                "IPv6",
            ]),
            Row::new(vec![
                {
                    if self.selected_protocols.contains(&NetworkProtocol::Icmp) {
                        " "
                    } else {
                        ""
                    }
                },
                "ICMP",
            ]),
        ];

        let network_filters_table = Table::new(network_filters, widths)
            .row_highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .title(" Network Filters 󱪤 ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if is_focused {
                    BorderType::Thick
                } else {
                    BorderType::default()
                })
                .border_style(Style::default().fg(Color::Green)),
            area,
        );

        frame.render_stateful_widget(
            network_filters_table,
            area.inner(ratatui::layout::Margin {
                horizontal: 6,
                vertical: 2,
            }),
            &mut self.state,
        );
    }
}
