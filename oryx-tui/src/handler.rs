use crate::{
    app::{App, AppResult, Mode},
    event::Event,
    phase::Phase,
    popup::PopupEnum,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key_events(key_event: KeyEvent, app: &mut App) -> AppResult<()> {
    // handle global key events
    if app.mode == Mode::Normal {
        match key_event.code {
            KeyCode::Char('?') => {
                app.phase.popup = Some(PopupEnum::Help);
                return Ok(());
            }
            KeyCode::Char('q') => {
                app.detach_ebpf();
                app.quit();
            }

            KeyCode::Char('c') | KeyCode::Char('C') => {
                if key_event.modifiers == KeyModifiers::CONTROL {
                    app.detach_ebpf();
                    app.quit();
                }
            }
            KeyCode::Char('r') => {
                if key_event.modifiers == KeyModifiers::CONTROL {
                    app.detach_ebpf();
                    app.notification_sender
                        .clone()
                        .unwrap()
                        .send(Event::Reset)?;
                    app.phase = Phase::new();
                    return Ok(());
                }
            }

            _ => {}
        }
    }
    app.phase.clone().handle_key_events(key_event, app);
    return Ok(());
}
