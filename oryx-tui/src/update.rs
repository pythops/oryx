use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::Stylize;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout},
    style::Style,
    widgets::{Block, BorderType, Borders, Clear},
    Frame,
};
use tui_big_text::{BigText, PixelSize};

use crate::app::App;
use crate::filters::direction::TrafficDirection;
use crate::phase::{Phase, Step};
use crate::sections::section::Section;
use crate::traits::ScrollableMenuComponent;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateBlockEnum {
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

impl UpdateBlockEnum {
    pub fn next(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            UpdateBlockEnum::TransportFilter => UpdateBlockEnum::NetworkFilter,
            UpdateBlockEnum::NetworkFilter => UpdateBlockEnum::LinkFilter,
            UpdateBlockEnum::LinkFilter => UpdateBlockEnum::TrafficDirection,
            UpdateBlockEnum::TrafficDirection => UpdateBlockEnum::Start,
            UpdateBlockEnum::Start => UpdateBlockEnum::TransportFilter,
        };
        app.filter_update = x;
        x.set_state(app, Some(0));
    }
    pub fn previous(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            UpdateBlockEnum::TransportFilter => UpdateBlockEnum::Start,
            UpdateBlockEnum::NetworkFilter => UpdateBlockEnum::TransportFilter,
            UpdateBlockEnum::LinkFilter => UpdateBlockEnum::NetworkFilter,
            UpdateBlockEnum::TrafficDirection => UpdateBlockEnum::LinkFilter,
            UpdateBlockEnum::Start => UpdateBlockEnum::TrafficDirection,
        };
        app.filter_update = x;
        x.set_state(app, Some(0));
    }

    fn app_component(self, app: &mut App) -> Option<Box<&mut dyn ScrollableMenuComponent>> {
        match self {
            UpdateBlockEnum::TransportFilter => Some(Box::new(&mut app.filter.transport)),
            UpdateBlockEnum::NetworkFilter => Some(Box::new(&mut app.filter.network)),
            UpdateBlockEnum::LinkFilter => Some(Box::new(&mut app.filter.link)),
            UpdateBlockEnum::TrafficDirection => Some(Box::new(&mut app.filter.traffic_direction)),
            UpdateBlockEnum::Start => None,
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
            KeyCode::Char(' ') => match self.app_component(app) {
                Some(p) => p.select(),
                _ => {}
            },
            KeyCode::Enter => {
                app.filter.network.apply();
                app.filter.transport.apply();
                app.filter.link.apply();
                app.filter.traffic_direction.apply();

                let traffic_dir = &app.filter.traffic_direction.applied_direction;
                if traffic_dir.contains(&TrafficDirection::Ingress) {
                    app.load_ingress();
                }
                if traffic_dir.contains(&TrafficDirection::Egress) {
                    app.load_egress();
                }

                app.phase = Phase {
                    step: Step::Sniffing(Section::Packet),
                    popup: None,
                }
            }
            KeyCode::Esc => app.phase.popup = None,
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

        app.filter.transport.render(
            frame,
            transport_filter_block,
            *self == UpdateBlockEnum::TransportFilter,
        );

        app.filter.network.render(
            frame,
            network_filter_block,
            *self == UpdateBlockEnum::NetworkFilter,
        );

        app.filter.link.render(
            frame,
            link_filter_block,
            *self == UpdateBlockEnum::LinkFilter,
        );

        app.filter.traffic_direction.render(
            frame,
            traffic_direction_block,
            *self == UpdateBlockEnum::TrafficDirection,
        );

        let apply = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if *self == UpdateBlockEnum::Start {
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
