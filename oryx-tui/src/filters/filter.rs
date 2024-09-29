use oryx_common::protocols::Protocol;
use ratatui::{
    layout::{Alignment, Constraint, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Row, Table},
    Frame,
};

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
}