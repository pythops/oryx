use std::{thread, time::Duration};

use crate::{
    app::{ActivePopup, App, AppResult},
    event::Event,
    export::export,
    filter::direction::TrafficDirection,
    notification::{Notification, NotificationLevel},
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
                app.filter
                    .start(sender.clone(), app.data_channel_sender.clone());

                app.start_sniffing = true;
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
                app.filter.handle_key_events(key_event);
            }
        }
        return Ok(());
    }

    // Sniff Phase

    if let Some(popup) = app.active_popup {
        match key_event.code {
            KeyCode::Esc => {
                app.active_popup = None;
                if popup == ActivePopup::UpdateFilters {
                    app.filter.handle_key_events(key_event);
                }
            }
            KeyCode::Enter => {
                if popup == ActivePopup::UpdateFilters {
                    app.filter
                        .update(sender.clone(), app.data_channel_sender.clone())?;
                    app.active_popup = None;
                }
            }
            _ => {
                if popup == ActivePopup::UpdateFilters {
                    app.filter.handle_key_events(key_event);
                }
            }
        }

        return Ok(());
    }

    if app.is_editing {
        if key_event.code == KeyCode::Esc {
            app.is_editing = false
        }

        app.section.handle_keys(key_event);
        return Ok(());
    }

    match key_event.code {
        KeyCode::Char('?') => {
            app.active_popup = Some(ActivePopup::Help);
        }

        KeyCode::Char('f') => {
            if app.active_popup.is_none() {
                app.active_popup = Some(ActivePopup::UpdateFilters);
                app.filter.trigger();
            }
        }

        KeyCode::Char('r') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.filter
                    .traffic_direction
                    .terminate(TrafficDirection::Ingress);
                app.filter
                    .traffic_direction
                    .terminate(TrafficDirection::Egress);
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
            app.is_editing = true;
            app.section.handle_keys(key_event);
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
