use crate::app::App;

use crate::popup::PopupEnum;
use crate::sections::section::Section;
use ratatui::{layout::Rect, Frame};
#[derive(Debug, Clone, PartialEq)]
pub enum PhaseEnum {
    Startup,
    Sniffing(Section),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Phase {
    pub phase_enum: PhaseEnum,
    pub popup: Option<PopupEnum>,
}
impl Phase {
    pub fn render(&self, frame: &mut Frame, area: Rect, app: &mut App) {
        match &self.phase_enum {
            PhaseEnum::Startup => app.startup.clone().render(frame, app),
            PhaseEnum::Sniffing(section) => section.render(frame, app),
        }
        match &self.popup {
            Some(popup) => popup.render(frame, area, app),
            _ => {}
        }
    }
    pub fn new() -> Self {
        Self {
            phase_enum: PhaseEnum::Startup,
            popup: None,
        }
    }
    pub fn handle_key_events(&mut self, key_event: crossterm::event::KeyEvent, app: &mut App) {
        match self.popup.as_mut() {
            Some(_) => {
                self.popup
                    .as_mut()
                    .unwrap()
                    .handle_key_events(key_event, app);
            }
            None => match &self.phase_enum {
                PhaseEnum::Startup => app.startup.clone().handle_key_events(key_event, app),
                PhaseEnum::Sniffing(mut section) => section.handle_key_events(key_event, app),
            },
        }
    }
}
