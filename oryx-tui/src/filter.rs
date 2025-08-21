pub mod direction;
pub mod fuzzy;
mod link;
mod network;
mod transport;

use crossterm::event::{KeyCode, KeyEvent};
use direction::TrafficDirectionFilter;
use link::LinkFilter;
use network::NetworkFilter;
use oryx_common::{
    RawData,
    protocols::{
        LinkProtocol, NB_LINK_PROTOCOL, NB_NETWORK_PROTOCOL, NB_TRANSPORT_PROTOCOL,
        NetworkProtocol, Protocol, TransportProtocol,
    },
};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Padding, Row, Table, TableState},
};
use transport::TransportFilter;
use tui_big_text::{BigText, PixelSize};

use crate::{
    app::AppResult,
    ebpf::{egress::load_egress, ingress::load_ingress},
    event::Event,
    interface::Interface,
    packet::direction::TrafficDirection,
    section::firewall::FirewallSignal,
};

#[derive(Debug, Clone)]
pub enum FilterChannelSignal {
    ProtoUpdate((Protocol, bool)),
    DirectionUpdate(bool),
    Kill,
}

#[derive(Debug, Clone)]
pub struct Channels<T> {
    pub sender: kanal::Sender<T>,
    pub receiver: kanal::Receiver<T>,
}

#[derive(Debug, Clone)]
pub struct IoChannels<T> {
    pub ingress: Channels<T>,
    pub egress: Channels<T>,
}

impl<T> Channels<T> {
    pub fn new() -> Self {
        let (sender, receiver) = kanal::unbounded();
        Self { sender, receiver }
    }
}

impl<T> IoChannels<T> {
    pub fn new() -> Self {
        Self {
            ingress: Channels::new(),
            egress: Channels::new(),
        }
    }
}

impl<T> Default for Channels<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Default for IoChannels<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FocusedBlock {
    Interface,
    TransportFilter,
    NetworkFilter,
    LinkFilter,
    TrafficDirection,
    Apply,
}

#[derive(Debug)]
pub struct Filter {
    pub interface: Interface,
    pub network: NetworkFilter,
    pub transport: TransportFilter,
    pub link: LinkFilter,
    pub traffic_direction: TrafficDirectionFilter,
    pub filter_chans: IoChannels<FilterChannelSignal>,
    pub firewall_chans: IoChannels<FirewallSignal>,
    pub focused_block: FocusedBlock,
}

impl Filter {
    pub fn new(
        firewall_chans: IoChannels<FirewallSignal>,
        interface_name: Option<String>,
        transport: Vec<TransportProtocol>,
        network: Vec<NetworkProtocol>,
        link: Vec<LinkProtocol>,
        direction: Vec<TrafficDirection>,
    ) -> Self {
        let focused_block = if interface_name.is_some() {
            FocusedBlock::Apply
        } else {
            FocusedBlock::Interface
        };

        Self {
            interface: Interface::new(interface_name),
            transport: TransportFilter::new(transport),
            network: NetworkFilter::new(network),
            link: LinkFilter::new(link),
            traffic_direction: TrafficDirectionFilter::new(direction),
            filter_chans: IoChannels::new(),
            firewall_chans,
            focused_block,
        }
    }

    pub fn terminate(&mut self) {
        // terminate packets reader threads
        self.traffic_direction.terminate(TrafficDirection::Egress);
        self.traffic_direction.terminate(TrafficDirection::Ingress);

        // terminate filter /packets sender threads
        let _ = self
            .filter_chans
            .ingress
            .sender
            .send(FilterChannelSignal::Kill);
        let _ = self
            .filter_chans
            .egress
            .sender
            .send(FilterChannelSignal::Kill);

        // terminate firewall threads
        let _ = self
            .firewall_chans
            .ingress
            .sender
            .send(FirewallSignal::Kill);
        let _ = self.firewall_chans.egress.sender.send(FirewallSignal::Kill);
    }

    pub fn start(
        &mut self,
        notification_sender: kanal::Sender<Event>,
        data_sender: kanal::Sender<([u8; RawData::LEN], TrafficDirection)>,
    ) -> AppResult<()> {
        let iface = self.interface.selected_interface.name.clone();

        self.apply();

        load_ingress(
            iface.clone(),
            notification_sender.clone(),
            data_sender.clone(),
            self.filter_chans.ingress.receiver.clone(),
            self.firewall_chans.ingress.receiver.clone(),
            self.traffic_direction.terminate_ingress.clone(),
        );

        load_egress(
            iface,
            notification_sender,
            data_sender,
            self.filter_chans.egress.receiver.clone(),
            self.firewall_chans.egress.receiver.clone(),
            self.traffic_direction.terminate_egress.clone(),
        );

        self.sync()?;

        Ok(())
    }

    pub fn trigger(&mut self) {
        self.network.selected_protocols = self.network.applied_protocols.clone();

        self.transport.selected_protocols = self.transport.applied_protocols.clone();

        self.link.selected_protocols = self.link.applied_protocols.clone();

        self.traffic_direction.selected_direction =
            self.traffic_direction.applied_direction.clone();

        self.transport.state = TableState::default().with_selected(0);

        self.focused_block = FocusedBlock::TransportFilter;
    }

    pub fn sync(&mut self) -> AppResult<()> {
        for protocol in TransportProtocol::all().iter() {
            if self.transport.applied_protocols.contains(protocol) {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Transport(*protocol),
                        false,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Transport(*protocol),
                        false,
                    )))?;
            } else {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Transport(*protocol),
                        true,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Transport(*protocol),
                        true,
                    )))?;
            }
        }

        for protocol in NetworkProtocol::all().iter() {
            if self.network.applied_protocols.contains(protocol) {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Network(*protocol),
                        false,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Network(*protocol),
                        false,
                    )))?;
            } else {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Network(*protocol),
                        true,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Network(*protocol),
                        true,
                    )))?;
            }
        }

        for protocol in LinkProtocol::all().iter() {
            if self.link.applied_protocols.contains(protocol) {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Link(*protocol),
                        false,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Link(*protocol),
                        false,
                    )))?;
            } else {
                self.filter_chans
                    .ingress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Link(*protocol),
                        true,
                    )))?;
                self.filter_chans
                    .egress
                    .sender
                    .send(FilterChannelSignal::ProtoUpdate((
                        Protocol::Link(*protocol),
                        true,
                    )))?;
            }
        }

        if self
            .traffic_direction
            .applied_direction
            .contains(&TrafficDirection::Ingress)
        {
            self.filter_chans
                .ingress
                .sender
                .send(FilterChannelSignal::DirectionUpdate(false))?;
        } else {
            self.filter_chans
                .ingress
                .sender
                .send(FilterChannelSignal::DirectionUpdate(true))?;
        }

        if self
            .traffic_direction
            .applied_direction
            .contains(&TrafficDirection::Egress)
        {
            self.filter_chans
                .egress
                .sender
                .send(FilterChannelSignal::DirectionUpdate(false))?;
        } else {
            self.filter_chans
                .egress
                .sender
                .send(FilterChannelSignal::DirectionUpdate(true))?;
        }

        Ok(())
    }

    pub fn handle_key_events(&mut self, key_event: KeyEvent, is_update_popup_displayed: bool) {
        match key_event.code {
            KeyCode::Tab => match self.focused_block {
                FocusedBlock::Interface => {
                    self.focused_block = FocusedBlock::TransportFilter;
                    self.interface.state.select(None);
                    self.transport.state.select(Some(0));
                }
                FocusedBlock::TransportFilter => {
                    self.focused_block = FocusedBlock::NetworkFilter;
                    self.network.state.select(Some(0));
                    self.transport.state.select(None);
                }

                FocusedBlock::NetworkFilter => {
                    self.focused_block = FocusedBlock::LinkFilter;
                    self.link.state.select(Some(0));
                    self.network.state.select(None);
                }

                FocusedBlock::LinkFilter => {
                    self.focused_block = FocusedBlock::TrafficDirection;
                    self.traffic_direction.state.select(Some(0));
                    self.link.state.select(None);
                }

                FocusedBlock::TrafficDirection => {
                    self.focused_block = FocusedBlock::Apply;
                    self.traffic_direction.state.select(None);
                }

                FocusedBlock::Apply => {
                    if is_update_popup_displayed {
                        self.focused_block = FocusedBlock::TransportFilter;
                    } else {
                        self.focused_block = FocusedBlock::Interface;
                        self.interface.state.select(Some(0));
                    }
                }
            },
            KeyCode::BackTab => match &self.focused_block {
                FocusedBlock::Interface => {
                    self.focused_block = FocusedBlock::Apply;
                    self.interface.state.select(None);
                }

                FocusedBlock::TransportFilter => {
                    if is_update_popup_displayed {
                        self.focused_block = FocusedBlock::Apply;
                        self.transport.state.select(None);
                    } else {
                        self.focused_block = FocusedBlock::Interface;
                        self.interface.state.select(Some(0));
                        self.transport.state.select(None);
                    }
                }

                FocusedBlock::NetworkFilter => {
                    self.focused_block = FocusedBlock::TransportFilter;
                    self.transport.state.select(Some(0));
                    self.network.state.select(None);
                }

                FocusedBlock::LinkFilter => {
                    self.focused_block = FocusedBlock::NetworkFilter;
                    self.network.state.select(Some(0));
                    self.link.state.select(None);
                }

                FocusedBlock::TrafficDirection => {
                    self.focused_block = FocusedBlock::LinkFilter;
                    self.link.state.select(Some(0));
                    self.traffic_direction.state.select(None);
                }

                FocusedBlock::Apply => {
                    self.focused_block = FocusedBlock::TrafficDirection;
                    self.traffic_direction.state.select(Some(0));
                }
            },

            KeyCode::Char('j') | KeyCode::Down => match &self.focused_block {
                FocusedBlock::Interface => {
                    self.interface.scroll_down();
                }
                FocusedBlock::TransportFilter => {
                    self.transport.scroll_down();
                }

                FocusedBlock::NetworkFilter => {
                    self.network.scroll_down();
                }

                FocusedBlock::LinkFilter => {
                    self.link.scroll_down();
                }

                FocusedBlock::TrafficDirection => {
                    self.traffic_direction.state.select(Some(1));
                }
                _ => {}
            },

            KeyCode::Char('k') | KeyCode::Up => match self.focused_block {
                FocusedBlock::Interface => {
                    self.interface.scroll_up();
                }
                FocusedBlock::TransportFilter => {
                    self.transport.scroll_up();
                }

                FocusedBlock::NetworkFilter => {
                    self.network.scroll_up();
                }

                FocusedBlock::LinkFilter => {
                    self.link.scroll_up();
                }

                FocusedBlock::TrafficDirection => {
                    self.traffic_direction.state.select(Some(0));
                }
                _ => {}
            },

            KeyCode::Char(' ') => match &self.focused_block {
                FocusedBlock::Interface => {
                    if let Some(index) = self.interface.state.selected() {
                        let net_interface = self.interface.interfaces[index].clone();
                        if net_interface.is_up {
                            self.interface.selected_interface =
                                self.interface.interfaces[index].clone();
                        }
                    }
                }
                FocusedBlock::NetworkFilter => {
                    self.network.select();
                }

                FocusedBlock::TransportFilter => {
                    self.transport.select();
                }

                FocusedBlock::LinkFilter => {
                    self.link.select();
                }

                FocusedBlock::TrafficDirection => {
                    self.traffic_direction.select();
                }

                _ => {}
            },

            _ => {}
        }
    }

    pub fn apply(&mut self) {
        self.network.apply();
        self.transport.apply();
        self.link.apply();
        self.traffic_direction.apply();
    }

    pub fn render_on_setup(&mut self, frame: &mut Frame) {
        let (filters_block, help_block) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Fill(1), Constraint::Length(3)])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .split(frame.area());

            (chunks[0], chunks[1])
        };

        let (
            interface_block,
            transport_filter_block,
            network_filter_block,
            link_filter_block,
            traffic_direction_block,
            start_block,
        ) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(self.interface.interfaces.len() as u16),
                    Constraint::Length(NB_TRANSPORT_PROTOCOL),
                    Constraint::Length(NB_NETWORK_PROTOCOL),
                    Constraint::Length(NB_LINK_PROTOCOL),
                    Constraint::Length(2),
                    Constraint::Length(4),
                ])
                .margin(1)
                .flex(Flex::SpaceAround)
                .split(filters_block);
            (
                chunks[0], chunks[1], chunks[2], chunks[3], chunks[4], chunks[5],
            )
        };

        self.interface.render_on_setup(
            frame,
            interface_block,
            self.focused_block == FocusedBlock::Interface,
        );

        self.network.render(
            frame,
            network_filter_block,
            self.focused_block == FocusedBlock::NetworkFilter,
            false,
        );

        self.transport.render(
            frame,
            transport_filter_block,
            self.focused_block == FocusedBlock::TransportFilter,
            false,
        );

        self.link.render(
            frame,
            link_filter_block,
            self.focused_block == FocusedBlock::LinkFilter,
            false,
        );

        self.traffic_direction.render(
            frame,
            traffic_direction_block,
            self.focused_block == FocusedBlock::TrafficDirection,
            false,
        );

        let start = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if self.focused_block == FocusedBlock::Apply {
                Style::default().white().bold()
            } else {
                Style::default().dark_gray()
            })
            .lines(vec!["START".into()])
            .centered()
            .build();

        frame.render_widget(start, start_block);

        let help = Text::from(vec![
            Line::from(""),
            Line::from(vec![
                Span::from("k,").bold(),
                Span::from("  Up").bold(),
                Span::from(" | ").bold(),
                Span::from("j,").bold(),
                Span::from("  Down").bold(),
                Span::from(" | ").bold(),
                Span::from("󱁐 ").bold(),
                Span::from(" Toggle Select").bold(),
                Span::from(" | ").bold(),
                Span::from("󱞦 ").bold(),
                Span::from(" Apply").bold(),
                Span::from(" | ").bold(),
                Span::from(" ").bold(),
                Span::from(" Nav").bold(),
            ]),
        ])
        .blue()
        .centered();

        frame.render_widget(
            help,
            help_block.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );
    }

    pub fn render_on_sniffing(&mut self, frame: &mut Frame, block: Rect) {
        let (filter_summury_block, interface_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(1),
                    Constraint::Percentage(50),
                ])
                .split(block);

            (chunks[0], chunks[2])
        };

        self.interface.render_on_sniffing(frame, interface_block);

        let widths = [Constraint::Length(10), Constraint::Fill(1)];
        let filters = {
            [
                Row::new(vec![
                    Line::styled("Transport", Style::new().bold()),
                    Line::from_iter(
                        TransportFilter::new(TransportProtocol::all().to_vec())
                            .selected_protocols
                            .iter()
                            .map(|filter| {
                                if self.transport.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_red(),
                                    )
                                }
                            }),
                    ),
                ]),
                Row::new(vec![
                    Line::styled("Network", Style::new().bold()),
                    Line::from_iter(
                        NetworkFilter::new(NetworkProtocol::all().to_vec())
                            .selected_protocols
                            .iter()
                            .map(|filter| {
                                if self.network.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_red(),
                                    )
                                }
                            }),
                    ),
                ]),
                Row::new(vec![
                    Line::styled("Link", Style::new().bold()),
                    Line::from_iter(
                        LinkFilter::new(LinkProtocol::all().to_vec())
                            .selected_protocols
                            .iter()
                            .map(|filter| {
                                if self.link.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {filter}  "),
                                        Style::default().light_red(),
                                    )
                                }
                            }),
                    ),
                ]),
                Row::new(vec![
                    Line::styled("Direction", Style::new().bold()),
                    Line::from_iter(
                        TrafficDirectionFilter::new(TrafficDirection::all().to_vec())
                            .selected_direction
                            .iter()
                            .map(|filter| {
                                if self.traffic_direction.applied_direction.contains(filter) {
                                    Span::styled(
                                        format!("󰞁 {filter}  "),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!("󰿝 {filter}  "),
                                        Style::default().light_red(),
                                    )
                                }
                            }),
                    ),
                ]),
            ]
        };

        let table = Table::new(filters, widths).column_spacing(3).block(
            Block::default()
                .title(" Filters 󱪤 ")
                .title_style(Style::default().bold().green())
                .title_alignment(Alignment::Center)
                .padding(Padding::horizontal(2))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
        );

        frame.render_widget(table, filter_summury_block);
    }

    pub fn render_update_popup(&mut self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(30),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Min(50),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        let (
            transport_filter_block,
            network_filter_block,
            link_filter_block,
            traffic_direction_block,
            apply_block,
        ) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(NB_TRANSPORT_PROTOCOL),
                    Constraint::Length(NB_NETWORK_PROTOCOL),
                    Constraint::Length(NB_LINK_PROTOCOL),
                    Constraint::Length(2),
                    Constraint::Length(4),
                ])
                .margin(1)
                .flex(Flex::SpaceBetween)
                .split(block);
            (chunks[1], chunks[2], chunks[3], chunks[4], chunks[5])
        };

        frame.render_widget(Clear, block);

        frame.render_widget(
            Block::new()
                .borders(Borders::all())
                .border_type(BorderType::Thick)
                .border_style(Style::default().green()),
            block,
        );

        self.network.render(
            frame,
            network_filter_block,
            self.focused_block == FocusedBlock::NetworkFilter,
            true,
        );

        self.transport.render(
            frame,
            transport_filter_block,
            self.focused_block == FocusedBlock::TransportFilter,
            true,
        );

        self.link.render(
            frame,
            link_filter_block,
            self.focused_block == FocusedBlock::LinkFilter,
            true,
        );

        self.traffic_direction.render(
            frame,
            traffic_direction_block,
            self.focused_block == FocusedBlock::TrafficDirection,
            true,
        );

        let apply = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if self.focused_block == FocusedBlock::Apply {
                Style::default().white().bold()
            } else {
                Style::default().dark_gray()
            })
            .lines(vec!["APPLY".into()])
            .centered()
            .build();
        frame.render_widget(apply, apply_block);
    }
}
