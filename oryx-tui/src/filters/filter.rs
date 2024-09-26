use oryx_common::protocols::{
    Protocol, NB_LINK_PROTOCOL, NB_NETWORK_PROTOCOL, NB_TRANSPORT_PROTOCOL,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Row, Table},
    Frame,
};
use tui_big_text::{BigText, PixelSize};

use crate::app::FocusedBlock;

use super::{
    direction::TrafficDirectionFilter, link::LinkFilter, network::NetworkFilter,
    transport::TransportFilter,
};

#[derive(Debug, Clone)]
pub struct FilterChannel {
    pub sender: kanal::Sender<(Protocol, bool)>,
    pub receiver: kanal::Receiver<(Protocol, bool)>,
}

impl FilterChannel {
    pub fn new() -> Self {
        let (sender, receiver) = kanal::unbounded();
        Self { sender, receiver }
    }
}

impl Default for FilterChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Filter {
    pub network: NetworkFilter,
    pub transport: TransportFilter,
    pub link: LinkFilter,
    pub traffic_direction: TrafficDirectionFilter,
    pub ingress_channel: FilterChannel,
    pub egress_channel: FilterChannel,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    pub fn new() -> Self {
        Self {
            network: NetworkFilter::new(),
            transport: TransportFilter::new(),
            link: LinkFilter::new(),
            traffic_direction: TrafficDirectionFilter::new(),
            ingress_channel: FilterChannel::new(),
            egress_channel: FilterChannel::new(),
        }
    }

    pub fn render_on_setup(
        &mut self,
        frame: &mut Frame,
        block: Rect,
        focused_block: &FocusedBlock,
    ) {
        let (
            transport_filter_block,
            network_filter_block,
            link_filter_block,
            traffic_direction_block,
        ) = {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                    Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                    Constraint::Length(NB_LINK_PROTOCOL + 4),
                    Constraint::Length(6),
                ])
                .margin(1)
                .flex(Flex::SpaceAround)
                .split(block);
            (chunks[0], chunks[1], chunks[2], chunks[3])
        };

        self.network
            .render(frame, network_filter_block, focused_block);

        self.transport
            .render(frame, transport_filter_block, focused_block);

        self.link.render(frame, link_filter_block, focused_block);

        self.traffic_direction
            .render(frame, traffic_direction_block, focused_block);
    }

    pub fn render_on_sniffing(&mut self, frame: &mut Frame, block: Rect) {
        let widths = [Constraint::Length(10), Constraint::Fill(1)];
        let filters = {
            [
                Row::new(vec![
                    Line::styled("Transport", Style::new().bold()),
                    Line::from_iter(TransportFilter::new().selected_protocols.iter().map(
                        |filter| {
                            if self.transport.applied_protocols.contains(filter) {
                                Span::styled(
                                    format!(" {}  ", filter),
                                    Style::default().light_green(),
                                )
                            } else {
                                Span::styled(
                                    format!(" {}  ", filter),
                                    Style::default().light_red(),
                                )
                            }
                        },
                    )),
                ]),
                Row::new(vec![
                    Line::styled("Network", Style::new().bold()),
                    Line::from_iter(
                        NetworkFilter::new()
                            .selected_protocols
                            .iter()
                            .map(|filter| {
                                if self.network.applied_protocols.contains(filter) {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!(" {}  ", filter),
                                        Style::default().light_red(),
                                    )
                                }
                            }),
                    ),
                ]),
                Row::new(vec![
                    Line::styled("Link", Style::new().bold()),
                    Line::from_iter(LinkFilter::new().selected_protocols.iter().map(|filter| {
                        if self.link.applied_protocols.contains(filter) {
                            Span::styled(format!(" {}  ", filter), Style::default().light_green())
                        } else {
                            Span::styled(format!(" {}  ", filter), Style::default().light_red())
                        }
                    })),
                ]),
                Row::new(vec![
                    Line::styled("Direction", Style::new().bold()),
                    Line::from_iter(
                        TrafficDirectionFilter::default()
                            .selected_direction
                            .iter()
                            .map(|filter| {
                                if self.traffic_direction.applied_direction.contains(filter) {
                                    Span::styled(
                                        format!("󰞁 {}  ", filter),
                                        Style::default().light_green(),
                                    )
                                } else {
                                    Span::styled(
                                        format!("󰿝 {}  ", filter),
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

        frame.render_widget(table, block);
    }

    pub fn update(&mut self, frame: &mut Frame, block: Rect, focused_block: &FocusedBlock) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(40),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(block);

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(60),
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
                    Constraint::Length(NB_TRANSPORT_PROTOCOL + 4),
                    Constraint::Length(NB_NETWORK_PROTOCOL + 4),
                    Constraint::Length(NB_LINK_PROTOCOL + 4),
                    Constraint::Length(6),
                    Constraint::Length(4),
                ])
                .margin(1)
                .flex(Flex::SpaceBetween)
                .split(block);
            (chunks[0], chunks[1], chunks[2], chunks[3], chunks[4])
        };

        frame.render_widget(Clear, block);
        frame.render_widget(
            Block::new()
                .borders(Borders::all())
                .border_type(BorderType::Thick)
                .border_style(Style::default().green()),
            block,
        );

        self.transport
            .render(frame, transport_filter_block, focused_block);

        self.network
            .render(frame, network_filter_block, focused_block);

        self.link.render(frame, link_filter_block, focused_block);

        self.traffic_direction
            .render(frame, traffic_direction_block, focused_block);

        let apply = BigText::builder()
            .pixel_size(PixelSize::Sextant)
            .style(if *focused_block == FocusedBlock::Start {
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
