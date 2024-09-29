use crate::app::{App, FocusedBlock};

use crate::event::Event;
use crate::mode::Mode;
use crate::ScrollableMenuComponent;
use crossterm::event::{KeyCode, KeyEvent};

use ratatui::prelude::Stylize;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout},
    style::Style,
    Frame,
};
use tui_big_text::{BigText, PixelSize};

use super::direction::TrafficDirection;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum StartMenuBlock {
    Interface,
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

impl StartMenuBlock {
    pub fn next(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            StartMenuBlock::Interface => StartMenuBlock::TransportFilter,
            StartMenuBlock::TransportFilter => StartMenuBlock::NetworkFilter,
            StartMenuBlock::NetworkFilter => StartMenuBlock::LinkFilter,
            StartMenuBlock::LinkFilter => StartMenuBlock::TrafficDirection,
            StartMenuBlock::TrafficDirection => StartMenuBlock::Start,
            StartMenuBlock::Start => StartMenuBlock::Interface,
        };
        app.focused_block = FocusedBlock::StartMenuBlock(x);
        x.set_state(app, Some(0));
    }
    pub fn previous(self, app: &mut App) {
        self.set_state(app, None);
        let x = match self {
            StartMenuBlock::Interface => StartMenuBlock::Start,
            StartMenuBlock::TransportFilter => StartMenuBlock::Interface,
            StartMenuBlock::NetworkFilter => StartMenuBlock::TransportFilter,
            StartMenuBlock::LinkFilter => StartMenuBlock::NetworkFilter,
            StartMenuBlock::TrafficDirection => StartMenuBlock::LinkFilter,
            StartMenuBlock::Start => StartMenuBlock::TrafficDirection,
        };
        app.focused_block = FocusedBlock::StartMenuBlock(x);
        x.set_state(app, Some(0));
    }

    fn app_component(self, app: &mut App) -> Option<Box<&mut dyn ScrollableMenuComponent>> {
        match self {
            StartMenuBlock::Interface => Some(Box::new(&mut app.interface)),
            StartMenuBlock::TransportFilter => Some(Box::new(&mut app.filter.transport)),
            StartMenuBlock::NetworkFilter => Some(Box::new(&mut app.filter.network)),
            StartMenuBlock::LinkFilter => Some(Box::new(&mut app.filter.link)),
            StartMenuBlock::TrafficDirection => Some(Box::new(&mut app.filter.traffic_direction)),
            StartMenuBlock::Start => None,
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

    pub fn handle_key_events(
        &mut self,
        key_event: KeyEvent,
        app: &mut App,
        sender: kanal::Sender<Event>,
    ) {
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
                    app.load_ingress(&sender);
                }
                if traffic_dir.contains(&TrafficDirection::Egress) {
                    app.load_egress(&sender);
                }

                app.start_sniffing = true;
                app.focused_block = FocusedBlock::Main(Mode::Packet);
            }
            _ => {}
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

        // interfaces
        app.interface
            .render_on_setup(frame, interface_block, &app.focused_block);

        // Filters
        app.filter
            .render_on_setup(frame, filter_block, &app.focused_block);

        // Start Button
        let start = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if *self == StartMenuBlock::Start {
                Style::default().white().bold()
            } else {
                Style::default().dark_gray()
            })
            .lines(vec!["START".into()])
            .centered()
            .build();
        frame.render_widget(start, start_block);
    }
}
