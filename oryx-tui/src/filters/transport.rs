use std::fmt::Display;

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Frame,
};

use crate::app::FocusedBlock;

pub const NB_TRANSPORT_PROTOCOL: u16 = 2;

#[derive(Debug)]
pub struct TransportFilter {
    pub state: TableState,
    pub selected_protocols: Vec<TransportProtocol>,
    pub applied_protocols: Vec<TransportProtocol>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

impl Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::TCP => write!(f, "Tcp"),
            TransportProtocol::UDP => write!(f, "Udp"),
        }
    }
}

impl Default for TransportFilter {
    fn default() -> Self {
        Self {
            state: TableState::default(),
            selected_protocols: vec![TransportProtocol::TCP, TransportProtocol::UDP],
            applied_protocols: Vec::new(),
        }
    }
}

impl TransportFilter {
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
        ];

        let table = Table::new(transport_filters, widths)
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .title(" Transport Filters 󱪤 ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if *focused_block == FocusedBlock::TransportFilter {
                    BorderType::Thick
                } else {
                    BorderType::default()
                })
                .border_style(Style::default().fg(Color::Green)),
            area,
        );

        frame.render_stateful_widget(
            table,
            area.inner(ratatui::layout::Margin {
                horizontal: 6,
                vertical: 2,
            }),
            &mut self.state,
        );
    }
}
