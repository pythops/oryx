use std::fmt::Display;

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Frame,
};

use crate::app::FocusedBlock;

pub const NB_NETWORK_PROTOCOL: u16 = 3;

#[derive(Debug)]
pub struct NetworkFilter {
    pub state: TableState,
    pub selected_protocols: Vec<NetworkProtocol>,
    pub applied_protocols: Vec<NetworkProtocol>,
}

impl Default for NetworkFilter {
    fn default() -> Self {
        NetworkFilter {
            state: TableState::default(),
            selected_protocols: vec![
                NetworkProtocol::Ipv4,
                NetworkProtocol::Ipv6,
                NetworkProtocol::Icmp,
            ],
            applied_protocols: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
    Icmp,
}

impl Display for NetworkProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkProtocol::Ipv4 => write!(f, "Ipv4"),
            NetworkProtocol::Ipv6 => write!(f, "Ipv6"),
            NetworkProtocol::Icmp => write!(f, "Icmp"),
        }
    }
}

impl NetworkFilter {
    pub fn apply(&mut self) {
        self.applied_protocols = self.selected_protocols.clone();
        self.selected_protocols.clear();
    }
    pub fn render(&mut self, frame: &mut Frame, block: Rect, focused_block: &FocusedBlock) {
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
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .title(" Network Filters 󱪤 ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if *focused_block == FocusedBlock::NetworkFilter {
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
