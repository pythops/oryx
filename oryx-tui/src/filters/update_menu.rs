use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::Stylize;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout},
    style::Style,
    widgets::{Block, BorderType, Borders, Clear, TableState},
    Frame,
};
use tui_big_text::{BigText, PixelSize};

use crate::app::App;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateFilterMenuBlock {
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

impl UpdateFilterMenuBlock {
    pub fn next(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            UpdateFilterMenuBlock::TransportFilter => UpdateFilterMenuBlock::NetworkFilter,
            UpdateFilterMenuBlock::NetworkFilter => UpdateFilterMenuBlock::LinkFilter,
            UpdateFilterMenuBlock::LinkFilter => UpdateFilterMenuBlock::TrafficDirection,
            UpdateFilterMenuBlock::TrafficDirection => UpdateFilterMenuBlock::Start,
            UpdateFilterMenuBlock::Start => UpdateFilterMenuBlock::TransportFilter,
        };
        self.select(app);
    }
    pub fn app_component(self, app: &mut App) -> Option<&mut TableState> {
        match self {
            UpdateFilterMenuBlock::TransportFilter => Some(&mut (*app).filter.transport.state),
            UpdateFilterMenuBlock::NetworkFilter => Some(&mut (*app).filter.network.state),
            UpdateFilterMenuBlock::LinkFilter => Some(&mut (*app).filter.link.state),
            UpdateFilterMenuBlock::TrafficDirection => {
                Some(&mut (*app).filter.traffic_direction.state)
            }
            UpdateFilterMenuBlock::Start => None,
        }
    }
    pub fn previous(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            UpdateFilterMenuBlock::TransportFilter => UpdateFilterMenuBlock::Start,
            UpdateFilterMenuBlock::NetworkFilter => UpdateFilterMenuBlock::TransportFilter,
            UpdateFilterMenuBlock::LinkFilter => UpdateFilterMenuBlock::NetworkFilter,
            UpdateFilterMenuBlock::TrafficDirection => UpdateFilterMenuBlock::LinkFilter,
            UpdateFilterMenuBlock::Start => UpdateFilterMenuBlock::TrafficDirection,
        };
        self.select(app);
    }

    pub fn select(self, app: &mut App) {
        match self.app_component(app) {
            Some(p) => {
                p.select(Some(0));
            }
            None => {}
        }
    }
    fn unselect(self, app: &mut App) {
        match self.app_component(app) {
            Some(p) => {
                p.select(None);
            }
            None => {}
        }
    }
    pub fn scroll_up(self, app: &mut App) {
        match self {
            UpdateFilterMenuBlock::TransportFilter => (*app).filter.transport.scroll_up(),
            UpdateFilterMenuBlock::NetworkFilter => (*app).filter.network.scroll_up(),
            UpdateFilterMenuBlock::LinkFilter => (*app).filter.link.scroll_up(),
            UpdateFilterMenuBlock::TrafficDirection => {
                (*app).filter.traffic_direction.state.select(Some(0))
            }
            _ => {}
        }
    }

    pub fn scroll_down(self, app: &mut App) {
        match self {
            UpdateFilterMenuBlock::TransportFilter => (*app).filter.transport.scroll_down(),
            UpdateFilterMenuBlock::NetworkFilter => (*app).filter.network.scroll_down(),
            UpdateFilterMenuBlock::LinkFilter => (*app).filter.link.scroll_down(),
            UpdateFilterMenuBlock::TrafficDirection => {
                (*app).filter.traffic_direction.state.select(Some(1))
            }
            _ => {}
        }
    }
    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Tab => {
                self.next(app);
            }
            KeyCode::BackTab => {
                self.previous(app);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_up(app);
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_down(app);
            }

            KeyCode::Esc => {
                app.focused_block = app.previous_focused_block.clone();
                app.update_filters = false;
            }
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
