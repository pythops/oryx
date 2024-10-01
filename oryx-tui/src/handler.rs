use std::{thread, time::Duration};
use tui_input::backend::crossterm::EventHandler;

use crate::{
    app::{ActivePopup, App, AppResult, Section},
    event::Event,
    export::export,
    filter::direction::TrafficDirection,
    notification::{Notification, NotificationLevel},
};
use ratatui::crossterm::{
    self,
    event::{KeyCode, KeyEvent, KeyModifiers},
};

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

    let fuzzy = app.fuzzy.clone();
    let mut fuzzy = fuzzy.lock().unwrap();

    if app.is_editing {
        match key_event.code {
            KeyCode::Esc => {
                app.is_editing = false;
                if !fuzzy.is_paused() {
                    fuzzy.pause();
                }
            }
            _ => {
                if !fuzzy.is_paused() {
                    fuzzy
                        .filter
                        .handle_event(&crossterm::event::Event::Key(key_event));
                }
            }
        }
        return Ok(());
    }

    match key_event.code {
        KeyCode::Esc => {
            if fuzzy.is_paused() {
                if app.manuall_scroll {
                    app.manuall_scroll = false;
                } else {
                    fuzzy.disable();
                }
            } else {
                fuzzy.pause();
            }
        }

        KeyCode::Tab => match app.section {
            Section::Packet => app.section = Section::Stats,
            Section::Stats => app.section = Section::Alerts,
            Section::Alerts => app.section = Section::Packet,
        },

        KeyCode::BackTab => {
            match app.section {
                Section::Packet => app.section = Section::Alerts,
                Section::Stats => app.section = Section::Packet,
                Section::Alerts => app.section = Section::Stats,
            };
        }

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

        _ => {
            if app.section == Section::Packet {
                match key_event.code {
                    KeyCode::Char('/') => {
                        fuzzy.enable();
                        fuzzy.unpause();
                        app.is_editing = true;
                    }

                    KeyCode::Char('i') => {
                        if app.packet_index.is_none() && fuzzy.packets.is_empty() {
                            return Ok(());
                        }

                        app.active_popup = Some(ActivePopup::PacketInfos);
                    }

                    KeyCode::Char('s') => {
                        if app.start_sniffing {
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
                                        Notification::send(
                                            e.to_string(),
                                            NotificationLevel::Error,
                                            sender,
                                        )?;
                                    }
                                }
                            }
                        }
                    }

                    KeyCode::Char('j') | KeyCode::Down => {
                        let app_packets = app.packets.lock().unwrap();

                        if !app.manuall_scroll {
                            app.manuall_scroll = true;
                            if fuzzy.is_enabled() {
                                fuzzy.packet_end_index = fuzzy.packets.len();
                            } else {
                                app.packet_end_index = app_packets.len();
                            }
                        }
                        if fuzzy.is_enabled() {
                            fuzzy.scroll_down(app.packet_window_size);
                        } else {
                            let i = match app.packets_table_state.selected() {
                                Some(i) => {
                                    if i < app.packet_window_size - 1 {
                                        i + 1
                                    } else if i == app.packet_window_size - 1
                                        && app_packets.len() > app.packet_end_index
                                    {
                                        // shit the window by one
                                        app.packet_end_index += 1;
                                        i + 1
                                    } else {
                                        i
                                    }
                                }
                                None => app_packets.len(),
                            };

                            app.packets_table_state.select(Some(i));
                        }
                    }

                    KeyCode::Char('k') | KeyCode::Up => {
                        let app_packets = app.packets.lock().unwrap();
                        if !app.manuall_scroll {
                            app.manuall_scroll = true;
                            // Record the last position. Usefull for selecting the packets to display
                            if fuzzy.is_enabled() {
                                fuzzy.packet_end_index = fuzzy.packets.len();
                            } else {
                                app.packet_end_index = app_packets.len();
                            }
                        }
                        if fuzzy.is_enabled() {
                            fuzzy.scroll_up(app.packet_window_size);
                        } else {
                            let i = match app.packets_table_state.selected() {
                                Some(i) => {
                                    if i > 1 {
                                        i - 1
                                    } else if i == 0
                                        && app.packet_end_index > app.packet_window_size
                                    {
                                        // shit the window by one
                                        app.packet_end_index -= 1;
                                        0
                                    } else {
                                        0
                                    }
                                }
                                None => app.packet_window_size,
                            };

                            app.packets_table_state.select(Some(i));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
