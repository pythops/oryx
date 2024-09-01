use std::{
    fmt::Display,
    sync::{atomic::AtomicBool, Arc},
};

use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Frame,
};

use crate::app::FocusedBlock;

#[derive(Debug)]
pub struct TrafficDirectionFilter {
    pub state: TableState,
    pub selected_direction: Vec<TrafficDirection>,
    pub applied_direction: Vec<TrafficDirection>,
    pub terminate_ingress: Arc<AtomicBool>,
    pub terminate_egress: Arc<AtomicBool>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

impl Display for TrafficDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficDirection::Ingress => write!(f, "Ingress"),
            TrafficDirection::Egress => write!(f, "Egress"),
        }
    }
}

impl Default for TrafficDirectionFilter {
    fn default() -> Self {
        TrafficDirectionFilter {
            state: TableState::default(),
            selected_direction: vec![TrafficDirection::Ingress, TrafficDirection::Egress],
            applied_direction: Vec::new(),
            terminate_ingress: Arc::new(AtomicBool::new(false)),
            terminate_egress: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl TrafficDirectionFilter {
    pub fn apply(&mut self) {
        self.applied_direction = self.selected_direction.clone();
        self.selected_direction.clear();
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect, focused_block: &FocusedBlock) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(55),
                Constraint::Fill(1),
            ])
            .flex(Flex::Center)
            .split(block);

        let area = layout[1];

        let widths = [Constraint::Length(2), Constraint::Fill(1)];
        let filters = vec![
            Row::new(vec![
                {
                    if self.selected_direction.contains(&TrafficDirection::Ingress) {
                        " "
                    } else {
                        ""
                    }
                },
                "Ingress",
            ]),
            Row::new(vec![
                {
                    if self.selected_direction.contains(&TrafficDirection::Egress) {
                        " "
                    } else {
                        ""
                    }
                },
                "Egress",
            ]),
        ];

        let table = Table::new(filters, widths)
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .title(" Traffic Direction 󰞁 ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if *focused_block == FocusedBlock::TrafficDirection {
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
