use oryx_common::protocols::{LinkProtocol, NB_LINK_PROTOCOL};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Text,
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
};

#[derive(Debug)]
pub struct LinkFilter {
    pub state: TableState,
    pub selected_protocols: Vec<LinkProtocol>,
    pub applied_protocols: Vec<LinkProtocol>,
}

impl LinkFilter {
    pub fn new(protocols: Vec<LinkProtocol>) -> Self {
        Self {
            state: TableState::default(),
            selected_protocols: protocols,
            applied_protocols: Vec::new(),
        }
    }

    pub fn select(&mut self) {
        if self.state.selected().is_some() {
            let protocol = LinkProtocol::Arp;
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
            Text::from("Link Filters 󱪤  ").bold()
        } else {
            Text::from("Link Filters 󱪤  ")
        };
        frame.render_widget(title, title_block);

        //

        let area = layout[2];

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
            .row_highlight_style(Style::new().bg(ratatui::style::Color::DarkGray));

        frame.render_widget(
            Block::new()
                .borders(Borders::LEFT)
                .border_type(if is_focused {
                    BorderType::QuadrantInside
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
