use crate::app::App;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateFilterMenuBLock {
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Start,
}

impl UpdateFilterMenuBLock {
    pub fn next(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            UpdateFilterMenuBLock::TransportFilter => UpdateFilterMenuBLock::NetworkFilter,
            UpdateFilterMenuBLock::NetworkFilter => UpdateFilterMenuBLock::LinkFilter,
            UpdateFilterMenuBLock::LinkFilter => UpdateFilterMenuBLock::TrafficDirection,
            UpdateFilterMenuBLock::TrafficDirection => UpdateFilterMenuBLock::Start,
            UpdateFilterMenuBLock::Start => UpdateFilterMenuBLock::TransportFilter,
        };
        self.select(app);
    }
    pub fn app_component(self, app: &mut App) -> Option<&mut TableState> {
        match self {
            UpdateFilterMenuBLock::TransportFilter => Some(&mut (*app).filter.transport.state),
            UpdateFilterMenuBLock::NetworkFilter => Some(&mut (*app).filter.network.state),
            UpdateFilterMenuBLock::LinkFilter => Some(&mut (*app).filter.link.state),
            UpdateFilterMenuBLock::TrafficDirection => {
                Some(&mut (*app).filter.traffic_direction.state)
            }
            UpdateFilterMenuBLock::Start => None,
        }
    }
    pub fn previous(&mut self, app: &mut App) {
        self.unselect(app);
        *self = match self {
            UpdateFilterMenuBLock::TransportFilter => UpdateFilterMenuBLock::Start,
            UpdateFilterMenuBLock::NetworkFilter => UpdateFilterMenuBLock::TransportFilter,
            UpdateFilterMenuBLock::LinkFilter => UpdateFilterMenuBLock::NetworkFilter,
            UpdateFilterMenuBLock::TrafficDirection => UpdateFilterMenuBLock::LinkFilter,
            UpdateFilterMenuBLock::Start => UpdateFilterMenuBLock::TrafficDirection,
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
            UpdateFilterMenuBLock::TransportFilter => (*app).filter.transport.scroll_up(),
            UpdateFilterMenuBLock::NetworkFilter => (*app).filter.network.scroll_up(),
            UpdateFilterMenuBLock::LinkFilter => (*app).filter.link.scroll_up(),
            UpdateFilterMenuBLock::TrafficDirection => {
                (*app).filter.traffic_direction.state.select(Some(0))
            }
            _ => {}
        }
    }

    pub fn scroll_down(self, app: &mut App) {
        match self {
            UpdateFilterMenuBLock::TransportFilter => (*app).filter.transport.scroll_down(),
            UpdateFilterMenuBLock::NetworkFilter => (*app).filter.network.scroll_down(),
            UpdateFilterMenuBLock::LinkFilter => (*app).filter.link.scroll_down(),
            UpdateFilterMenuBLock::TrafficDirection => {
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
                app.focused_block = app.previous_focused_block;
                app.update_filters = false;
            }
            _ => {}
        }
    }
    pub fn render(&mut self, frame: &mut Frame, app: App) {
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
                    Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                    Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                    Constraint::Length(NB_LINK_PROTOCOL + 4),
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
            .render(frame, transport_filter_block, self);

        app.filter.network.render(frame, network_filter_block, self);

        app.filter.link.render(frame, link_filter_block, self);

        app.filter
            .traffic_direction
            .render(frame, traffic_direction_block, self);

        let apply = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if *self == UpdateFilterMenuBLock::Start {
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
