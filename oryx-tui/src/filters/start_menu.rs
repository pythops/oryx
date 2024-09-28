use crate::app::App;

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
    pub fn next(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            StartMenuBlock::Interface => StartMenuBlock::TransportFilter,
            StartMenuBlock::TransportFilter => StartMenuBlock::NetworkFilter,
            StartMenuBlock::NetworkFilter => StartMenuBlock::LinkFilter,
            StartMenuBlock::LinkFilter => StartMenuBlock::TrafficDirection,
            StartMenuBlock::TrafficDirection => StartMenuBlock::Start,
            StartMenuBlock::Start => StartMenuBlock::Interface,
        };
        self.select(app);
    }
    pub fn app_component(self, app: &mut App) -> Option<&mut TableState> {
        match self {
            StartMenuBlock::Interface => Some(&mut app.interface.state),
            StartMenuBlock::TransportFilter => Some(&mut (*app).filter.transport.state),
            StartMenuBlock::NetworkFilter => Some(&mut (*app).filter.network.state),
            StartMenuBlock::LinkFilter => Some(&mut (*app).filter.link.state),
            StartMenuBlock::TrafficDirection => Some(&mut (*app).filter.traffic_direction.state),
            StartMenuBlock::Start => None,
        }
    }
    pub fn previous(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            StartMenuBlock::Interface => StartMenuBlock::Start,
            StartMenuBlock::TransportFilter => StartMenuBlock::Interface,
            StartMenuBlock::NetworkFilter => StartMenuBlock::TransportFilter,
            StartMenuBlock::LinkFilter => StartMenuBlock::NetworkFilter,
            StartMenuBlock::TrafficDirection => StartMenuBlock::LinkFilter,
            StartMenuBlock::Start => StartMenuBlock::TrafficDirection,
        };
        self.select(app);
    }

    fn select(self, app: &mut App) {
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
            StartMenuBlock::Interface => app.interface.scroll_up(),
            StartMenuBlock::TransportFilter => (*app).filter.transport.scroll_up(),
            StartMenuBlock::NetworkFilter => (*app).filter.network.scroll_up(),
            StartMenuBlock::LinkFilter => (*app).filter.link.scroll_up(),
            StartMenuBlock::TrafficDirection => {
                (*app).filter.traffic_direction.state.select(Some(0))
            }
            _ => {}
        }
    }

    pub fn scroll_down(self, app: &mut App) {
        match self {
            StartMenuBlock::Interface => app.interface.scroll_down(),
            StartMenuBlock::TransportFilter => (*app).filter.transport.scroll_down(),
            StartMenuBlock::NetworkFilter => (*app).filter.network.scroll_down(),
            StartMenuBlock::LinkFilter => (*app).filter.link.scroll_down(),
            StartMenuBlock::TrafficDirection => {
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
            _ => {}
        }
    }
    pub fn render(&mut self, frame: &mut Frame, app: &mut App) {
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
        app.interface.render_on_setup(frame, interface_block, &self);

        // Filters
        app.filter.render_on_setup(frame, filter_block, &self);

        // Start Button
        let start = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if self.focused_block == FocusedBlock::Start {
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
