use crate::{app::App, popup::ActivePopup};

use crate::sections::section::Section;
use ratatui::Frame;
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Startup,
    Sniffing(Section),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Phase {
    pub step: Step,
    pub popup: Option<ActivePopup>,
}

impl Phase {
    pub fn render(&mut self, frame: &mut Frame, app: &mut App) {
        match self.step {
            Step::Startup => app.startup.clone().render(frame, app),
            Step::Sniffing(section) => section.render(frame, app),
        }
        match self.popup {
            Some(popup) => popup.render(frame, app),
            _ => {}
        }
    }
    pub fn new() -> Self {
        Self {
            step: Step::Startup,
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
            None => match &self.step {
                Step::Startup => app.startup.clone().handle_key_events(key_event, app),
                Step::Sniffing(mut section) => section.handle_key_events(key_event, app),
            },
        }
    }
}
