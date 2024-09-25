use oryx_common::protocols::{LinkProtocol, NetworkProtocol, Protocol, TransportProtocol};
use std::{thread, time::Duration};
use tui_input::backend::crossterm::EventHandler;

use crate::{
    app::{App, AppResult, FocusedBlock, Mode},
    ebpf::Ebpf,
    event::Event,
    export::export,
    filters::direction::TrafficDirection,
    notification::{Notification, NotificationLevel},
};
use ratatui::{
    crossterm::{
        self,
        event::{KeyCode, KeyEvent, KeyModifiers},
    },
    widgets::TableState,
};

pub fn handle_key_events(
    key_event: KeyEvent,
    app: &mut App,
    sender: kanal::Sender<Event>,
) -> AppResult<()> {
    if app.show_packet_infos_popup {
        if key_event.code == KeyCode::Esc {
            app.show_packet_infos_popup = false;
        }

        return Ok(());
    }

    let fuzzy = app.fuzzy.clone();
    let mut fuzzy = fuzzy.lock().unwrap();

    if fuzzy.is_enabled() {
        match key_event.code {
            KeyCode::Esc => {
                if app.focused_block == FocusedBlock::Help {
                    app.focused_block = FocusedBlock::Main;
                    return Ok(());
                }

                if app.update_filters {
                    app.update_filters = false;
                    return Ok(());
                }

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

            KeyCode::Tab => {
                if app.focused_block == FocusedBlock::Help {
                    return Ok(());
                }

                if app.update_filters {
                    match &app.focused_block {
                        FocusedBlock::TransportFilter => {
                            app.focused_block = FocusedBlock::NetworkFilter;
                            app.filter.network.state.select(Some(0));
                            app.filter.transport.state.select(Some(0));
                        }

                        FocusedBlock::NetworkFilter => {
                            app.focused_block = FocusedBlock::LinkFilter;
                            app.filter.link.state.select(Some(0));
                            app.filter.network.state.select(None);
                        }

                        FocusedBlock::LinkFilter => {
                            app.focused_block = FocusedBlock::TrafficDirection;
                            app.filter.traffic_direction.state.select(Some(0));
                            app.filter.link.state.select(None);
                        }

                        FocusedBlock::TrafficDirection => {
                            app.focused_block = FocusedBlock::Start;
                            app.filter.traffic_direction.state.select(None);
                        }

                        FocusedBlock::Start => {
                            app.focused_block = FocusedBlock::TransportFilter;
                        }
                        _ => {}
                    };

                    return Ok(());
                }

                match app.mode {
                    Mode::Packet => app.mode = Mode::Stats,
                    Mode::Stats => app.mode = Mode::Alerts,
                    Mode::Alerts => app.mode = Mode::Packet,
                }
            }

            KeyCode::BackTab => {
                if app.start_sniffing {
                    if app.focused_block == FocusedBlock::Help {
                        return Ok(());
                    }

                    if app.update_filters {
                        match &app.focused_block {
                            FocusedBlock::TransportFilter => {
                                app.focused_block = FocusedBlock::Start;
                                app.filter.transport.state.select(None);
                            }

                            FocusedBlock::NetworkFilter => {
                                app.focused_block = FocusedBlock::TransportFilter;
                                app.filter.transport.state.select(Some(0));
                                app.filter.network.state.select(None);
                            }

                            FocusedBlock::LinkFilter => {
                                app.focused_block = FocusedBlock::NetworkFilter;
                                app.filter.network.state.select(Some(0));
                                app.filter.link.state.select(None);
                            }

                            FocusedBlock::TrafficDirection => {
                                app.focused_block = FocusedBlock::LinkFilter;
                                app.filter.link.state.select(Some(0));
                                app.filter.traffic_direction.state.select(None);
                            }

                            FocusedBlock::Start => {
                                app.focused_block = FocusedBlock::TrafficDirection;
                                app.filter.traffic_direction.state.select(Some(0));
                            }
                            _ => {}
                        }
                    }
                }
            }

            _ => {
                if app.focused_block == FocusedBlock::Help {
                    return Ok(());
                }
                if !fuzzy.is_paused() && !app.update_filters {
                    fuzzy
                        .filter
                        .handle_event(&crossterm::event::Event::Key(key_event));
                } else {
                    match key_event.code {
                        KeyCode::Char('/') => {
                            if !app.update_filters {
                                fuzzy.unpause();
                            }
                        }

                        KeyCode::Char('?') => {
                            app.focused_block = FocusedBlock::Help;
                        }

                        KeyCode::Char('i') => {
                            if app.focused_block == FocusedBlock::Help || app.update_filters {
                                return Ok(());
                            }
                            if app.packet_index.is_none() || fuzzy.packets.is_empty() {
                                return Ok(());
                            }

                            app.show_packet_infos_popup = true;
                        }

                        KeyCode::Char('f') => {
                            if app.focused_block != FocusedBlock::Help && app.start_sniffing {
                                app.update_filters = true;
                                app.focused_block = FocusedBlock::TransportFilter;

                                app.filter.network.selected_protocols =
                                    app.filter.network.applied_protocols.clone();

                                app.filter.transport.selected_protocols =
                                    app.filter.transport.applied_protocols.clone();

                                app.filter.link.selected_protocols =
                                    app.filter.link.applied_protocols.clone();

                                app.filter.traffic_direction.selected_direction =
                                    app.filter.traffic_direction.applied_direction.clone();

                                app.filter.transport.state = TableState::default().with_selected(0);
                            }
                        }

                        KeyCode::Char('j') | KeyCode::Down => {
                            if !app.update_filters {
                                if !app.manuall_scroll {
                                    app.manuall_scroll = true;
                                    // Record the last position. Usefull for selecting the packets to display
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                }
                                let i = match fuzzy.scroll_state.selected() {
                                    Some(i) => {
                                        if i < app.packet_window_size - 1 {
                                            i + 1
                                        } else if i == app.packet_window_size - 1
                                            && fuzzy.packets.len() > fuzzy.packet_end_index
                                        {
                                            // shit the window by one
                                            fuzzy.packet_end_index += 1;
                                            i + 1
                                        } else {
                                            i
                                        }
                                    }
                                    None => fuzzy.packets.len(),
                                };

                                fuzzy.scroll_state.select(Some(i));
                            } else {
                                match &app.focused_block {
                                    FocusedBlock::NetworkFilter => {
                                        app.filter.network.scroll_down();
                                    }

                                    FocusedBlock::TransportFilter => {
                                        app.filter.transport.scroll_down();
                                    }

                                    FocusedBlock::LinkFilter => {
                                        app.filter.link.scroll_down();
                                    }

                                    FocusedBlock::TrafficDirection => {
                                        app.filter.traffic_direction.state.select(Some(1));
                                    }

                                    _ => {}
                                };
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            if !app.update_filters {
                                if !app.manuall_scroll {
                                    app.manuall_scroll = true;
                                    // Record the last position. Usefull for selecting the packets to display
                                    fuzzy.packet_end_index = fuzzy.packets.len();
                                }
                                let i = match fuzzy.scroll_state.selected() {
                                    Some(i) => {
                                        if i > 1 {
                                            i - 1
                                        } else if i == 0
                                            && fuzzy.packet_end_index > app.packet_window_size
                                        {
                                            // shit the window by one
                                            fuzzy.packet_end_index -= 1;
                                            0
                                        } else {
                                            0
                                        }
                                    }
                                    None => fuzzy.packets.len(),
                                };

                                fuzzy.scroll_state.select(Some(i));
                            } else {
                                match &app.focused_block {
                                    FocusedBlock::NetworkFilter => {
                                        app.filter.network.scroll_up();
                                    }

                                    FocusedBlock::TransportFilter => {
                                        app.filter.transport.scroll_up();
                                    }

                                    FocusedBlock::LinkFilter => {
                                        app.filter.link.scroll_up();
                                    }

                                    FocusedBlock::TrafficDirection => {
                                        app.filter.traffic_direction.state.select(Some(0));
                                    }

                                    FocusedBlock::Help => {
                                        app.help.scroll_up();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    } else {
        match key_event.code {
            //TODO: add terminate method on ingress and egress
            KeyCode::Char('q') => {
                app.filter
                    .traffic_direction
                    .terminate_egress
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                app.filter
                    .traffic_direction
                    .terminate_ingress
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                thread::sleep(Duration::from_millis(110));
                app.quit();
            }

            KeyCode::Char('c') | KeyCode::Char('C') => {
                if key_event.modifiers == KeyModifiers::CONTROL {
                    app.filter
                        .traffic_direction
                        .terminate_egress
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    app.filter
                        .traffic_direction
                        .terminate_ingress
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(110));
                    app.quit();
                }
            }

            KeyCode::Esc => {
                if app.focused_block == FocusedBlock::Help {
                    if app.start_sniffing {
                        app.focused_block = FocusedBlock::Main
                    } else {
                        app.focused_block = app.previous_focused_block;
                    }
                    return Ok(());
                }

                if app.update_filters {
                    app.update_filters = false;
                    return Ok(());
                }

                if app.manuall_scroll {
                    app.manuall_scroll = false;
                }
            }

            KeyCode::Char('?') => {
                app.focused_block = FocusedBlock::Help;
            }

            KeyCode::Char('f') => {
                if app.focused_block != FocusedBlock::Help && app.start_sniffing {
                    app.update_filters = true;

                    app.focused_block = FocusedBlock::TransportFilter;

                    app.filter.network.selected_protocols =
                        app.filter.network.applied_protocols.clone();

                    app.filter.transport.selected_protocols =
                        app.filter.transport.applied_protocols.clone();

                    app.filter.link.selected_protocols = app.filter.link.applied_protocols.clone();

                    app.filter.traffic_direction.selected_direction =
                        app.filter.traffic_direction.applied_direction.clone();

                    app.filter.transport.state = TableState::default().with_selected(0);
                }
            }

            KeyCode::Char('s') => {
                if app.focused_block == FocusedBlock::Help || app.update_filters {
                    return Ok(());
                }

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

            KeyCode::Char('/') => {
                if app.focused_block == FocusedBlock::Help || app.update_filters {
                    return Ok(());
                }
                if app.start_sniffing {
                    fuzzy.enable();
                    fuzzy.unpause();
                }
            }

            KeyCode::Char('i') => {
                if app.focused_block == FocusedBlock::Help || app.update_filters {
                    return Ok(());
                }
                let packets = app.packets.lock().unwrap();

                if app.packet_index.is_none() || packets.is_empty() {
                    return Ok(());
                }

                app.show_packet_infos_popup = true;
            }

            KeyCode::Char('r') => {
                if app.focused_block == FocusedBlock::Help || app.update_filters {
                    return Ok(());
                }
                if key_event.modifiers == KeyModifiers::CONTROL {
                    app.filter
                        .traffic_direction
                        .terminate_egress
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    app.filter
                        .traffic_direction
                        .terminate_ingress
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(150));
                    sender.send(Event::Reset)?;
                }
            }

            KeyCode::Enter => {
                if app.focused_block == FocusedBlock::Start && !app.start_sniffing {
                    let iface = app.interface.selected_interface.name.clone();

                    app.filter.network.apply();
                    app.filter.transport.apply();
                    app.filter.link.apply();
                    app.filter.traffic_direction.apply();

                    if app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Ingress)
                    {
                        Ebpf::load_ingress(
                            iface.clone(),
                            sender.clone(),
                            app.data_channel_sender.clone(),
                            app.filter.ingress_channel.receiver.clone(),
                            app.filter.traffic_direction.terminate_ingress.clone(),
                        );
                    }

                    if app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Egress)
                    {
                        Ebpf::load_egress(
                            iface,
                            sender.clone(),
                            app.data_channel_sender.clone(),
                            app.filter.egress_channel.receiver.clone(),
                            app.filter.traffic_direction.terminate_egress.clone(),
                        );
                    }

                    app.start_sniffing = true;
                    app.focused_block = FocusedBlock::TransportFilter;
                } else if app.start_sniffing && app.update_filters {
                    // Remove egress
                    if app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Egress)
                        && !app
                            .filter
                            .traffic_direction
                            .selected_direction
                            .contains(&TrafficDirection::Egress)
                    {
                        app.filter
                            .traffic_direction
                            .terminate_egress
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Add egress
                    if !app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Egress)
                        && app
                            .filter
                            .traffic_direction
                            .selected_direction
                            .contains(&TrafficDirection::Egress)
                    {
                        app.filter
                            .traffic_direction
                            .terminate_egress
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        let iface = app.interface.selected_interface.name.clone();
                        Ebpf::load_egress(
                            iface,
                            sender.clone(),
                            app.data_channel_sender.clone(),
                            app.filter.egress_channel.receiver.clone(),
                            app.filter.traffic_direction.terminate_egress.clone(),
                        );
                    }

                    // Remove ingress
                    if app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Ingress)
                        && !app
                            .filter
                            .traffic_direction
                            .selected_direction
                            .contains(&TrafficDirection::Ingress)
                    {
                        app.filter
                            .traffic_direction
                            .terminate_ingress
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Add ingress
                    if !app
                        .filter
                        .traffic_direction
                        .applied_direction
                        .contains(&TrafficDirection::Ingress)
                        && app
                            .filter
                            .traffic_direction
                            .selected_direction
                            .contains(&TrafficDirection::Ingress)
                    {
                        let iface = app.interface.selected_interface.name.clone();
                        app.filter
                            .traffic_direction
                            .terminate_ingress
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        Ebpf::load_ingress(
                            iface,
                            sender.clone(),
                            app.data_channel_sender.clone(),
                            app.filter.ingress_channel.receiver.clone(),
                            app.filter.traffic_direction.terminate_ingress.clone(),
                        );
                    }
                    app.filter.network.apply();
                    app.filter.transport.apply();
                    app.filter.link.apply();
                    app.filter.traffic_direction.apply();

                    thread::sleep(Duration::from_millis(150));
                    app.filter
                        .traffic_direction
                        .terminate_ingress
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    app.filter
                        .traffic_direction
                        .terminate_ingress
                        .store(false, std::sync::atomic::Ordering::Relaxed);

                    app.update_filters = false;
                }

                for protocol in TransportProtocol::all().iter() {
                    if app.filter.transport.applied_protocols.contains(protocol) {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Transport(*protocol), false))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Transport(*protocol), false))?;
                    } else {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Transport(*protocol), true))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Transport(*protocol), true))?;
                    }
                }

                for protocol in NetworkProtocol::all().iter() {
                    if app.filter.network.applied_protocols.contains(protocol) {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Network(*protocol), false))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Network(*protocol), false))?;
                    } else {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Network(*protocol), true))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Network(*protocol), true))?;
                    }
                }

                for protocol in LinkProtocol::all().iter() {
                    if app.filter.link.applied_protocols.contains(protocol) {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Link(*protocol), false))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Link(*protocol), false))?;
                    } else {
                        app.filter
                            .ingress_channel
                            .sender
                            .send((Protocol::Link(*protocol), true))?;
                        app.filter
                            .egress_channel
                            .sender
                            .send((Protocol::Link(*protocol), true))?;
                    }
                }
            }

            KeyCode::Tab => {
                if app.start_sniffing {
                    if app.focused_block == FocusedBlock::Help {
                        return Ok(());
                    }

                    if app.update_filters {
                        match &app.focused_block {
                            FocusedBlock::TransportFilter => {
                                app.focused_block = FocusedBlock::NetworkFilter;
                                app.filter.network.state.select(Some(0));
                                app.filter.transport.state.select(None);
                            }

                            FocusedBlock::NetworkFilter => {
                                app.focused_block = FocusedBlock::LinkFilter;
                                app.filter.link.state.select(Some(0));
                                app.filter.network.state.select(None);
                            }

                            FocusedBlock::LinkFilter => {
                                app.focused_block = FocusedBlock::TrafficDirection;
                                app.filter.traffic_direction.state.select(Some(0));
                                app.filter.link.state.select(None);
                            }

                            FocusedBlock::TrafficDirection => {
                                app.focused_block = FocusedBlock::Start;
                                app.filter.traffic_direction.state.select(None);
                            }

                            FocusedBlock::Start => {
                                app.focused_block = FocusedBlock::TransportFilter;
                                app.filter.transport.state.select(Some(0));
                            }
                            _ => {}
                        };

                        return Ok(());
                    }

                    match app.mode {
                        Mode::Packet => app.mode = Mode::Stats,
                        Mode::Stats => app.mode = Mode::Alerts,
                        Mode::Alerts => app.mode = Mode::Packet,
                    };
                } else {
                    match &app.focused_block {
                        FocusedBlock::Interface => {
                            app.focused_block = FocusedBlock::TransportFilter;
                            app.previous_focused_block = app.focused_block;
                            app.interface.state.select(None);
                            app.filter.transport.state.select(Some(0));
                        }

                        FocusedBlock::TransportFilter => {
                            app.focused_block = FocusedBlock::NetworkFilter;
                            app.previous_focused_block = app.focused_block;
                            app.filter.network.state.select(Some(0));
                            app.filter.transport.state.select(None);
                        }

                        FocusedBlock::NetworkFilter => {
                            app.focused_block = FocusedBlock::LinkFilter;
                            app.previous_focused_block = app.focused_block;
                            app.filter.link.state.select(Some(0));
                            app.filter.network.state.select(None);
                        }

                        FocusedBlock::LinkFilter => {
                            app.focused_block = FocusedBlock::TrafficDirection;
                            app.previous_focused_block = app.focused_block;
                            app.filter.traffic_direction.state.select(Some(0));
                            app.filter.link.state.select(None);
                        }

                        FocusedBlock::TrafficDirection => {
                            app.focused_block = FocusedBlock::Start;
                            app.previous_focused_block = app.focused_block;
                            app.filter.traffic_direction.state.select(None);
                        }

                        FocusedBlock::Start => {
                            app.focused_block = FocusedBlock::Interface;
                            app.previous_focused_block = app.focused_block;
                            app.interface.state.select(Some(0));
                        }
                        _ => {}
                    }
                }
            }

            KeyCode::BackTab => {
                if app.start_sniffing {
                    if app.focused_block == FocusedBlock::Help {
                        return Ok(());
                    }

                    if app.update_filters {
                        match &app.focused_block {
                            FocusedBlock::TransportFilter => {
                                app.focused_block = FocusedBlock::Start;
                                app.filter.transport.state.select(None);
                            }

                            FocusedBlock::NetworkFilter => {
                                app.focused_block = FocusedBlock::TransportFilter;
                                app.filter.transport.state.select(Some(0));
                                app.filter.network.state.select(None);
                            }

                            FocusedBlock::LinkFilter => {
                                app.focused_block = FocusedBlock::NetworkFilter;
                                app.filter.network.state.select(Some(0));
                                app.filter.link.state.select(None);
                            }

                            FocusedBlock::TrafficDirection => {
                                app.focused_block = FocusedBlock::LinkFilter;
                                app.filter.link.state.select(Some(0));
                                app.filter.traffic_direction.state.select(None);
                            }

                            FocusedBlock::Start => {
                                app.focused_block = FocusedBlock::TrafficDirection;
                                app.filter.traffic_direction.state.select(Some(0));
                            }
                            _ => {}
                        }
                        return Ok(());
                    };

                    match app.mode {
                        Mode::Packet => app.mode = Mode::Alerts,
                        Mode::Stats => app.mode = Mode::Packet,
                        Mode::Alerts => app.mode = Mode::Stats,
                    };
                } else {
                    match &app.focused_block {
                        FocusedBlock::Interface => {
                            app.focused_block = FocusedBlock::Start;
                            app.interface.state.select(None);
                        }

                        FocusedBlock::TransportFilter => {
                            app.focused_block = FocusedBlock::Interface;
                            app.interface.state.select(Some(0));
                            app.filter.transport.state.select(None);
                        }

                        FocusedBlock::NetworkFilter => {
                            app.focused_block = FocusedBlock::TransportFilter;
                            app.filter.transport.state.select(Some(0));
                            app.filter.network.state.select(None);
                        }

                        FocusedBlock::LinkFilter => {
                            app.focused_block = FocusedBlock::NetworkFilter;
                            app.filter.network.state.select(Some(0));
                            app.filter.link.state.select(None);
                        }

                        FocusedBlock::TrafficDirection => {
                            app.focused_block = FocusedBlock::LinkFilter;
                            app.filter.link.state.select(Some(0));
                            app.filter.traffic_direction.state.select(None);
                        }

                        FocusedBlock::Start => {
                            app.focused_block = FocusedBlock::TrafficDirection;
                            app.filter.traffic_direction.state.select(Some(0));
                        }
                        _ => {}
                    }
                }
            }

            KeyCode::Char(' ') => {
                if !app.start_sniffing || app.update_filters {
                    match &app.focused_block {
                        FocusedBlock::Interface => {
                            if let Some(index) = app.interface.state.selected() {
                                let net_interface = app.interface.interfaces[index].clone();
                                if net_interface.is_up {
                                    app.interface.selected_interface =
                                        app.interface.interfaces[index].clone();
                                }
                            }
                        }
                        FocusedBlock::NetworkFilter => {
                            app.filter.network.select();
                        }

                        FocusedBlock::TransportFilter => {
                            app.filter.transport.select();
                        }

                        FocusedBlock::LinkFilter => {
                            app.filter.link.select();
                        }

                        FocusedBlock::TrafficDirection => {
                            app.filter.traffic_direction.select();
                        }

                        _ => {}
                    }
                }
            }

            KeyCode::Char('j') | KeyCode::Down => {
                if let FocusedBlock::Help = app.focused_block {
                    return Ok(());
                }
                let app_packets = app.packets.lock().unwrap();
                // Sniff mode
                if app.start_sniffing && !app.update_filters {
                    if !app.manuall_scroll {
                        app.manuall_scroll = true;
                        // Record the last position. Usefull for selecting the packets to display
                        app.packet_end_index = app_packets.len();
                    }
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
                } else {
                    match &app.focused_block {
                        FocusedBlock::Interface => {
                            let i = match app.interface.state.selected() {
                                Some(i) => {
                                    if i < app.interface.interfaces.len() - 1 {
                                        i + 1
                                    } else {
                                        i
                                    }
                                }
                                None => 0,
                            };

                            app.interface.state.select(Some(i));
                        }

                        FocusedBlock::NetworkFilter => {
                            app.filter.network.scroll_down();
                        }

                        FocusedBlock::TransportFilter => {
                            app.filter.transport.scroll_down();
                        }

                        FocusedBlock::LinkFilter => {
                            app.filter.link.scroll_down();
                        }

                        FocusedBlock::TrafficDirection => {
                            app.filter.traffic_direction.state.select(Some(1));
                        }

                        FocusedBlock::Help => {
                            app.help.scroll_down();
                        }
                        _ => {}
                    }
                }
            }

            KeyCode::Char('k') | KeyCode::Up => {
                let app_packets = app.packets.lock().unwrap();
                if let FocusedBlock::Help = app.focused_block {
                    return Ok(());
                }
                if app.start_sniffing && !app.update_filters {
                    if !app.manuall_scroll {
                        app.manuall_scroll = true;
                        // Record the last position. Usefull for selecting the packets to display
                        app.packet_end_index = app_packets.len();
                    }
                    let i = match app.packets_table_state.selected() {
                        Some(i) => {
                            if i > 1 {
                                i - 1
                            } else if i == 0 && app.packet_end_index > app.packet_window_size {
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
                } else {
                    match &app.focused_block {
                        FocusedBlock::Interface => {
                            let i = match app.interface.state.selected() {
                                Some(i) => {
                                    if i > 1 {
                                        i - 1
                                    } else {
                                        0
                                    }
                                }
                                None => 0,
                            };

                            app.interface.state.select(Some(i));
                        }
                        FocusedBlock::NetworkFilter => {
                            app.filter.network.scroll_up();
                        }

                        FocusedBlock::TransportFilter => {
                            app.filter.transport.scroll_up();
                        }

                        FocusedBlock::LinkFilter => {
                            app.filter.link.scroll_up();
                        }

                        FocusedBlock::TrafficDirection => {
                            app.filter.traffic_direction.state.select(Some(0));
                        }

                        FocusedBlock::Help => {
                            app.help.scroll_up();
                        }
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }

    Ok(())
}
