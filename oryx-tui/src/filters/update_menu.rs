use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::Stylize;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout},
    style::Style,
    widgets::{Block, BorderType, Borders, Clear},
    Frame,
};
use tui_big_text::{BigText, PixelSize};

use crate::app::{App, FocusedBlock};
use crate::ScrollableMenuComponent;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateFilterMenuBlock {
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

impl UpdateFilterMenuBlock {
    pub fn next(self, app: &mut App) {
        self.set_state(app, Some(0));
        let x = match self {
            UpdateFilterMenuBlock::TransportFilter => UpdateFilterMenuBlock::NetworkFilter,
            UpdateFilterMenuBlock::NetworkFilter => UpdateFilterMenuBlock::LinkFilter,
            UpdateFilterMenuBlock::LinkFilter => UpdateFilterMenuBlock::TrafficDirection,
            UpdateFilterMenuBlock::TrafficDirection => UpdateFilterMenuBlock::Start,
            UpdateFilterMenuBlock::Start => UpdateFilterMenuBlock::TransportFilter,
        };
        app.focused_block = FocusedBlock::UpdateFilterMenuBlock(x);
        self.set_state(app, None);
    }
    pub fn previous(self, app: &mut App) {
        self.set_state(app, Some(0));
        let x = match self {
            UpdateFilterMenuBlock::TransportFilter => UpdateFilterMenuBlock::Start,
            UpdateFilterMenuBlock::NetworkFilter => UpdateFilterMenuBlock::TransportFilter,
            UpdateFilterMenuBlock::LinkFilter => UpdateFilterMenuBlock::NetworkFilter,
            UpdateFilterMenuBlock::TrafficDirection => UpdateFilterMenuBlock::LinkFilter,
            UpdateFilterMenuBlock::Start => UpdateFilterMenuBlock::TrafficDirection,
        };
        app.focused_block = FocusedBlock::UpdateFilterMenuBlock(x);
        self.set_state(app, None);
    }

    fn app_component(self, app: &mut App) -> Option<Box<&mut dyn ScrollableMenuComponent>> {
        match self {
            UpdateFilterMenuBlock::TransportFilter => Some(Box::new(&mut app.filter.transport)),
            UpdateFilterMenuBlock::NetworkFilter => Some(Box::new(&mut app.filter.network)),
            UpdateFilterMenuBlock::LinkFilter => Some(Box::new(&mut app.filter.link)),
            UpdateFilterMenuBlock::TrafficDirection => {
                Some(Box::new(&mut app.filter.traffic_direction))
            }
            UpdateFilterMenuBlock::Start => None,
        }
    }

    fn set_state(self, app: &mut App, value: Option<usize>) {
        match self.app_component(app) {
            Some(p) => p.set_state(value),
            _ => {}
        }
    }

    pub fn scroll_up(self, app: &mut App) {
        match self.app_component(app) {
            Some(p) => p.scroll_up(),
            _ => {}
        }
    }
    pub fn scroll_down(self, app: &mut App) {
        match self.app_component(app) {
            Some(p) => p.scroll_down(),
            _ => {}
        }
    }
    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Tab => self.next(app),
            KeyCode::BackTab => self.previous(app),

            KeyCode::Char('k') | KeyCode::Up => self.scroll_up(app),

            KeyCode::Char('j') | KeyCode::Down => self.scroll_down(app),

            _ => {}
        }
    }
    pub fn render(&self, frame: &mut Frame, app: &mut App) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(40),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(60),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        let (
            transport_filter_block,
            network_filter_block,
            link_filter_block,
            traffic_direction_block,
            apply_block,
        ) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(oryx_common::protocols::NB_TRANSPORT_PROTOCOL + 4),
                    Constraint::Length(oryx_common::protocols::NB_NETWORK_PROTOCOL + 4),
                    Constraint::Length(oryx_common::protocols::NB_LINK_PROTOCOL + 4),
                    Constraint::Length(6),
                    Constraint::Length(4),
                ])
                .margin(1)
                .flex(Flex::SpaceBetween)
                .split(block);
            (chunks[0], chunks[1], chunks[2], chunks[3], chunks[4])
        };

        frame.render_widget(Clear, block);
        frame.render_widget(
            Block::new()
                .borders(Borders::all())
                .border_type(BorderType::Thick)
                .border_style(Style::default().green()),
            block,
        );

        app.filter
            .transport
            .render(frame, transport_filter_block, &app.focused_block);

        app.filter
            .network
            .render(frame, network_filter_block, &app.focused_block);

        app.filter
            .link
            .render(frame, link_filter_block, &app.focused_block);

        app.filter
            .traffic_direction
            .render(frame, traffic_direction_block, &app.focused_block);

        let apply = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if *self == UpdateFilterMenuBlock::Start {
                Style::default().white().bold()
            } else {
                Style::default().dark_gray()
            })
            .lines(vec!["APPLY".into()])
            .centered()
            .build();
        frame.render_widget(apply, apply_block);
    }
}
