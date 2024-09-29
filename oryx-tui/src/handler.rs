use crate::{
    app::{App, AppResult, FocusedBlock},
    event::Event,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn handle_key_events_help(key_event: KeyEvent, app: &mut App) {
    match key_event.code {
        KeyCode::Esc => app.focused_block = app.previous_focused_block.clone(),
        _ => {}
    }
}

pub fn handle_key_events(
    key_event: KeyEvent,
    app: &mut App,
    sender: kanal::Sender<Event>,
) -> AppResult<()> {
    // handle global key events
    if !app.is_editing {
        match key_event.code {
            KeyCode::Char('?') => {
                app.previous_focused_block = app.focused_block.clone();
                app.focused_block = FocusedBlock::Help;
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
                    sender.send(Event::Reset)?;
                    return Ok(());
                }
            }

            _ => {}
        }
    }
    match app.focused_block.clone() {
        FocusedBlock::Help => handle_key_events_help(key_event, app),
        FocusedBlock::StartMenuBlock(mut start_block) => {
            start_block.handle_key_events(key_event, app, sender)
        }
        FocusedBlock::UpdateFilterMenuBlock(mut update_block) => {
            update_block.handle_key_events(key_event, app)
        }
        FocusedBlock::Main(mut mode_block) => mode_block.handle_key_events(key_event, app),
    }
    return Ok(());
}
