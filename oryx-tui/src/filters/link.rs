use oryx_common::protocols::{LinkProtocol, NB_LINK_PROTOCOL};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Frame,
};

use crate::{app::FocusedBlock, MenuComponent, Scrollable};

use super::{start_menu::StartMenuBlock, update_menu::UpdateFilterMenuBlock};

#[derive(Debug)]
pub struct LinkFilter {
    pub state: TableState,
    pub selected_protocols: Vec<LinkProtocol>,
    pub applied_protocols: Vec<LinkProtocol>,
}

impl Default for LinkFilter {
    fn default() -> Self {
        Self::new()
    }
}
impl MenuComponent for LinkFilter {
    fn set_state(&mut self, value: Option<usize>) {
        self.state.select(value);
    }

    fn select(&mut self) {
        if self.state.selected().is_some() {
            let protocol = LinkProtocol::Arp;
            if self.selected_protocols.contains(&protocol) {
                self.selected_protocols.retain(|&p| p != protocol);
            } else {
                self.selected_protocols.push(protocol);
            }
        }
    }
}
impl Scrollable for LinkFilter {
    fn scroll_down(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i < (NB_LINK_PROTOCOL - 1).into() {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
    }

    fn scroll_up(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i > 1 {
                    i - 1
                } else {
                    0
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
    }
}

impl LinkFilter {
    pub fn new() -> Self {
        Self {
            state: TableState::default(),
            selected_protocols: vec![LinkProtocol::Arp],
            applied_protocols: Vec::new(),
        }
    }

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
        let link_filters = vec![Row::new(vec![
            {
                if self.selected_protocols.contains(&LinkProtocol::Arp) {
                    " "
                } else {
                    ""
                }
            },
            "ARP",
        ])];

        let table = Table::new(link_filters, widths)
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .title(" Link Filters 󱪤 ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(match *focused_block {
                    FocusedBlock::StartMenuBlock(StartMenuBlock::LinkFilter)
                    | FocusedBlock::UpdateFilterMenuBlock(UpdateFilterMenuBlock::LinkFilter) => {
                        BorderType::Thick
                    }
                    _ => BorderType::default(),
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
