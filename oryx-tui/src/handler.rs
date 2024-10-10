use std::{thread, time::Duration};

use crate::{
    app::{ActivePopup, App, AppResult},
    event::Event,
    filter::FocusedBlock,
    section::FocusedSection,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key_events(
    key_event: KeyEvent,
    app: &mut App,
    event_sender: kanal::Sender<Event>,
) -> AppResult<()> {
    // Start Phase
    if !app.start_sniffing {
        match key_event.code {
            KeyCode::Enter => {
                if app.filter.focused_block == FocusedBlock::Apply {
                    app.filter
                        .start(event_sender.clone(), app.data_channel_sender.clone())?;

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
                        app.section
                            .firewall
                            .handle_keys(key_event, event_sender.clone())?;
                        app.is_editing = false;
                    }
                    _ => {}
                }
            }
            KeyCode::Enter => match popup {
                ActivePopup::UpdateFilters => {
                    if app.filter.focused_block == FocusedBlock::Apply {
                        app.filter
                            .update(event_sender.clone(), app.data_channel_sender.clone())?;
                        if !app.filter.traffic_direction.is_ingress_loaded() {
                            app.section.firewall.disable_ingress_rules();
                        }

                        if !app.filter.traffic_direction.is_egress_loaded() {
                            app.section.firewall.disable_egress_rules();
                        }

                        app.active_popup = None;
                    }
                }
                ActivePopup::NewFirewallRule => {
                    if app
                        .section
                        .firewall
                        .handle_keys(key_event, event_sender.clone())
                        .is_ok()
                    {
                        app.active_popup = None;
                        app.is_editing = false;
                    }
                }
                _ => {}
            },

            _ => match popup {
                ActivePopup::UpdateFilters => {
                    app.filter.handle_key_events(key_event, true);
                }
                ActivePopup::NewFirewallRule => {
                    app.section
                        .firewall
                        .handle_keys(key_event, event_sender.clone())?;
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

        app.section.handle_keys(key_event, event_sender.clone())?;
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
                event_sender.send(Event::Reset)?;
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
                app.section.handle_keys(key_event, event_sender.clone())?;
            }
        }

        KeyCode::Char('n') | KeyCode::Char('e') => {
            if app.section.focused_section == FocusedSection::Firewall
                && app.section.handle_keys(key_event, event_sender).is_ok()
            {
                app.is_editing = true;
                app.active_popup = Some(ActivePopup::NewFirewallRule);
            }
        }

        KeyCode::Char('i') => {
            if app.section.inspection.can_show_popup() {
                app.active_popup = Some(ActivePopup::PacketInfos);
            }
        }

        KeyCode::Char(' ') => {
            if app.section.focused_section == FocusedSection::Firewall {
                app.section.firewall.load_rule(
                    event_sender.clone(),
                    app.filter.traffic_direction.is_ingress_loaded(),
                    app.filter.traffic_direction.is_egress_loaded(),
                )?;
            }
        }

        _ => {
            app.section.handle_keys(key_event, event_sender.clone())?;
        }
    }

    Ok(())
}
