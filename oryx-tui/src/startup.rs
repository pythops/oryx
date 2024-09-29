use crate::app::App;

use crate::filters::direction::TrafficDirection;
use crate::phase::{Phase, PhaseEnum};
use crate::popup::PopupEnum;
use crate::sections::section::Section;
use crate::traits::ScrollableMenuComponent;
use crossterm::event::{KeyCode, KeyEvent};

use oryx_common::protocols::{NB_LINK_PROTOCOL, NB_NETWORK_PROTOCOL, NB_TRANSPORT_PROTOCOL};

use ratatui::prelude::Stylize;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout},
    style::Style,
    Frame,
};
use tui_big_text::{BigText, PixelSize};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum StartupBlockEnum {
    Interface,
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Startup {
    pub focus_block: StartupBlockEnum,
    pub popup: Option<PopupEnum>,
}
impl Startup {
    pub fn new() -> Self {
        Startup {
            focus_block: StartupBlockEnum::Interface,
            popup: None,
        }
    }

    pub fn render(&self, frame: &mut Frame, app: &mut App) {
        let (interface_block, filter_block, start_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(app.interface.interfaces.len() as u16 + 6),
                    Constraint::Fill(1),
                    Constraint::Length(4),
                ])
                .margin(1)
                .flex(Flex::SpaceAround)
                .split(frame.area());
            (chunks[0], chunks[1], chunks[2])
        };
        let (
            transport_filter_block,
            network_filter_block,
            link_filter_block,
            traffic_direction_block,
        ) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                    Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                    Constraint::Length(NB_LINK_PROTOCOL + 4),
                    Constraint::Length(6),
                ])
                .margin(1)
                .flex(Flex::SpaceAround)
                .split(filter_block);
            (chunks[0], chunks[1], chunks[2], chunks[3])
        };
        // interfaces
        app.interface.render(
            frame,
            interface_block,
            self.focus_block == StartupBlockEnum::Interface,
        );

        app.filter.network.render(
            frame,
            network_filter_block,
            self.focus_block == StartupBlockEnum::NetworkFilter,
        );

        app.filter.transport.render(
            frame,
            transport_filter_block,
            self.focus_block == StartupBlockEnum::TransportFilter,
        );

        app.filter.link.render(
            frame,
            link_filter_block,
            self.focus_block == StartupBlockEnum::LinkFilter,
        );

        app.filter.traffic_direction.render(
            frame,
            traffic_direction_block,
            self.focus_block == StartupBlockEnum::TrafficDirection,
        );
        let start = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if self.focus_block == StartupBlockEnum::Start {
                Style::default().white().bold()
            } else {
                Style::default().dark_gray()
            })
            .lines(vec!["START".into()])
            .centered()
            .build();
        frame.render_widget(start, start_block);
    }
    // Filters

    // Start Button

    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Tab => self.focus_block.next(app),
            KeyCode::BackTab => self.focus_block.previous(app),
            KeyCode::Char('k') | KeyCode::Up => self.focus_block.scroll_up(app),
            KeyCode::Char('j') | KeyCode::Down => self.focus_block.scroll_down(app),
            KeyCode::Char(' ') => match self.focus_block.app_component(app) {
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
                    phase_enum: PhaseEnum::Sniffing(Section::Packet),
                    popup: None,
                }
            }
            _ => {}
        }
    }
}

impl StartupBlockEnum {
    pub fn next(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            StartupBlockEnum::Interface => StartupBlockEnum::TransportFilter,
            StartupBlockEnum::TransportFilter => StartupBlockEnum::NetworkFilter,
            StartupBlockEnum::NetworkFilter => StartupBlockEnum::LinkFilter,
            StartupBlockEnum::LinkFilter => StartupBlockEnum::TrafficDirection,
            StartupBlockEnum::TrafficDirection => StartupBlockEnum::Start,
            StartupBlockEnum::Start => StartupBlockEnum::Interface,
        };
        app.startup.focus_block = x;
        x.set_state(app, Some(0));
    }
    pub fn previous(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            StartupBlockEnum::Interface => StartupBlockEnum::Start,
            StartupBlockEnum::TransportFilter => StartupBlockEnum::Interface,
            StartupBlockEnum::NetworkFilter => StartupBlockEnum::TransportFilter,
            StartupBlockEnum::LinkFilter => StartupBlockEnum::NetworkFilter,
            StartupBlockEnum::TrafficDirection => StartupBlockEnum::LinkFilter,
            StartupBlockEnum::Start => StartupBlockEnum::TrafficDirection,
        };
        app.startup.focus_block = x;
        x.set_state(app, Some(0));
    }

    fn app_component(self, app: &mut App) -> Option<Box<&mut dyn ScrollableMenuComponent>> {
        match self {
            StartupBlockEnum::Interface => Some(Box::new(&mut app.interface)),
            StartupBlockEnum::TransportFilter => Some(Box::new(&mut app.filter.transport)),
            StartupBlockEnum::NetworkFilter => Some(Box::new(&mut app.filter.network)),
            StartupBlockEnum::LinkFilter => Some(Box::new(&mut app.filter.link)),
            StartupBlockEnum::TrafficDirection => Some(Box::new(&mut app.filter.traffic_direction)),
            StartupBlockEnum::Start => None,
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
}
