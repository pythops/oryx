use std::{thread, time::Duration};

use crate::{
    app::{ActivePopup, App, AppResult},
    event::Event,
    export::export,
    filter::FocusedBlock,
    notification::{Notification, NotificationLevel},
    section::{FocusedSection, Section},
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key_events(
    key_event: KeyEvent,
    app: &mut App,
    sender: kanal::Sender<Event>,
) -> AppResult<()> {
    // Start Phase
    if !app.start_sniffing {
        match key_event.code {
            KeyCode::Enter => {
                if app.filter.focused_block == FocusedBlock::Apply {
                    app.filter
                        .start(sender.clone(), app.data_channel_sender.clone());

                    app.start_sniffing = true;
                }
            }

            KeyCode::Esc => {
                app.active_popup = None;
            }

            KeyCode::Char('?') => {
                app.active_popup = Some(ActivePopup::Help);
            }

            KeyCode::Char('q') => {
                app.quit();
            }

            KeyCode::Char('c') | KeyCode::Char('C') => {
                if key_event.modifiers == KeyModifiers::CONTROL {
                    app.quit();
                }
            }
            _ => {
                app.filter.handle_key_events(key_event, false);
            }
        }
        return Ok(());
    }

    // Sniff Phase

    if let Some(popup) = app.active_popup {
        match key_event.code {
            KeyCode::Esc => {
                app.active_popup = None;
                match popup {
                    ActivePopup::UpdateFilters => {
                        app.filter.handle_key_events(key_event, true);
                    }
                    ActivePopup::NewFirewallRule => {
                        app.section.firewall.handle_keys(key_event);
                        app.is_editing = false;
                    }
                    _ => {}
                }
            }
            KeyCode::Enter => match popup {
                ActivePopup::UpdateFilters => {
                    if app.filter.focused_block == FocusedBlock::Apply {
                        app.filter
                            .update(sender.clone(), app.data_channel_sender.clone())?;

                        app.active_popup = None;
                    }
                }
                ActivePopup::NewFirewallRule => {
                    app.section.firewall.handle_keys(key_event);
                }
                _ => {}
            },

            _ => match popup {
                ActivePopup::UpdateFilters => {
                    app.filter.handle_key_events(key_event, true);
                }
                ActivePopup::NewFirewallRule => {
                    app.section.firewall.handle_keys(key_event);
                }
                _ => {}
            },
        }

        return Ok(());
    }

    if app.is_editing {
        match key_event.code {
            KeyCode::Esc | KeyCode::Enter => app.is_editing = false,
            _ => {}
        }

        app.section.handle_keys(key_event);
        return Ok(());
    }

    match key_event.code {
        KeyCode::Char('?') => {
            app.active_popup = Some(ActivePopup::Help);
        }

        KeyCode::Char('f') => {
            app.active_popup = Some(ActivePopup::UpdateFilters);
            app.filter.trigger();
        }

        KeyCode::Char('r') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.filter.terminate();
                thread::sleep(Duration::from_millis(150));
                sender.send(Event::Reset)?;
            }
        }

        KeyCode::Char('q') => {
            app.filter.terminate();
            thread::sleep(Duration::from_millis(110));
            app.quit();
        }

        KeyCode::Char('c') | KeyCode::Char('C') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.filter.terminate();
                thread::sleep(Duration::from_millis(110));
                app.quit();
            }
        }

        KeyCode::Char('/') => {
            if app.section.focused_section == FocusedSection::Inspection {
                app.is_editing = true;
                app.section.handle_keys(key_event);
            }
        }

        KeyCode::Char('n') => {
            if app.section.focused_section == FocusedSection::Firewall {
                app.is_editing = true;
                app.section.handle_keys(key_event);
                app.active_popup = Some(ActivePopup::NewFirewallRule);
            }
        }

        KeyCode::Char('i') => {
            if app.section.inspection.can_show_popup() {
                app.active_popup = Some(ActivePopup::PacketInfos);
            }
        }

        KeyCode::Char('s') => {
            let app_packets = app.packets.lock().unwrap();
            if app_packets.is_empty() {
                Notification::send(
                    "There is no packets".to_string(),
                    NotificationLevel::Info,
                    sender,
                )?;
            } else {
                match export(&app_packets) {
                    Ok(_) => {
                        Notification::send(
                            "Packets exported to ~/oryx/capture file".to_string(),
                            NotificationLevel::Info,
                            sender,
                        )?;
                    }
                    Err(e) => {
                        Notification::send(e.to_string(), NotificationLevel::Error, sender)?;
                    }
                }
            }
        }
        _ => {
            app.section.handle_keys(key_event);
        }
    }

    Ok(())
}
