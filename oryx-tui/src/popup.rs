use ratatui::Frame;

use crate::{app::App, packets::info::PacketInfo};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActivePopup {
    Help,
    FilterUpdate,
    PacketInfo,
}
impl ActivePopup {
    pub fn render(&self, frame: &mut Frame, app: &mut App) {
        match self {
            ActivePopup::Help => app.help.render(frame),
            ActivePopup::FilterUpdate => app.filter_update.clone().render(frame, app),
            ActivePopup::PacketInfo => PacketInfo::render(frame, app),
        }
    }

    pub fn handle_key_events(&mut self, key_event: crossterm::event::KeyEvent, app: &mut App) {
        match self {
            ActivePopup::Help => app.help.clone().handle_key_events(key_event, app),
            ActivePopup::FilterUpdate => {
                app.filter_update.clone().handle_key_events(key_event, app)
            }
            _ => {}
        }
    }
}
