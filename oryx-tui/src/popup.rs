use ratatui::{layout::Rect, Frame};

use crate::app::App;

#[derive(Debug, Clone, PartialEq)]
pub enum PopupEnum {
    Help,
    FilterUpdate,
}
impl PopupEnum {
    pub fn render(&self, frame: &mut Frame, _: Rect, app: &mut App) {
        match self {
            PopupEnum::Help => app.help.render(frame),
            PopupEnum::FilterUpdate => app.filter_update.clone().render(frame, app),
        }
    }
    pub fn handle_key_events(&mut self, key_event: crossterm::event::KeyEvent, app: &mut App) {
        match self {
            PopupEnum::Help => app.help.clone().handle_key_events(key_event, app),
            PopupEnum::FilterUpdate => app.filter_update.clone().handle_key_events(key_event, app),
        }
    }
}
