use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};

#[derive(Debug, Copy, Clone)]
pub struct Icmpv6Packet {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
}

impl Icmpv6Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("ICMP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height.is_multiple_of(2) {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Type", Style::new().bold()),
                Span::from(self.icmp_type.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Code", Style::new().bold()),
                Span::from(self.code.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().yellow())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );

        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

#[derive(Debug, Copy, Clone, strum::Display)]
pub enum IcmpType {
    #[strum(to_string = "Reserved")]
    Reserved,
    #[strum(to_string = "Destination Unreachable")]
    DestinationUnreachable = 1,
    #[strum(to_string = "Packet Too Big")]
    PacketTooBig = 2,
    #[strum(to_string = "Time Exceeded")]
    TimeExceeded = 3,
    #[strum(to_string = "Parameter Problem")]
    ParameterProblem = 4,
    #[strum(to_string = "Echo Request")]
    EchoRequest = 128,
    #[strum(to_string = "Echo Reply")]
    EchoReply = 129,
    #[strum(to_string = "Multicast Listener Query")]
    MulticastListenerQuery = 130,
    #[strum(to_string = "Multicast Listener Report")]
    MulticastListenerReport = 131,
    #[strum(to_string = "Multicast Listener Done")]
    MulticastListenerDone = 132,
    #[strum(to_string = "Router Solicitation")]
    RouterSolicitation = 133,
    #[strum(to_string = "Router Advertisement")]
    RouterAdvertisement = 134,
    #[strum(to_string = "Neighbor Solicitation")]
    NeighborSolicitation = 135,
    #[strum(to_string = "Neighbor Advertisement")]
    NeighborAdvertisement = 136,
    #[strum(to_string = "Redirect Message")]
    RedirectMessage = 137,
    #[strum(to_string = "Router Renumbering")]
    RouterRenumbering = 138,
    #[strum(to_string = "ICMP Node Information Query")]
    ICMPNodeInformationQuery = 139,
    #[strum(to_string = "ICMP Node Information Response")]
    ICMPNodeInformationResponse = 140,
    #[strum(to_string = "Inverse Neighbor Discovery Solicitation Message")]
    InverseNeighborDiscoverySolicitation = 141,
    #[strum(to_string = "Inverse Neighbor Discovery Advertisement Message")]
    InverseNeighborDiscoveryAdvertisement = 142,
    #[strum(to_string = "Home Agent Address Discovery Request Message")]
    HomeAgentAddressDiscoveryRequest = 144,
    #[strum(to_string = "Home Agent Address Discovery Reply Message")]
    HomeAgentAddressDiscoveryReply = 145,
    #[strum(to_string = "Mobile Prefix Solicitation")]
    MobilePrefixSolicitation = 146,
    #[strum(to_string = "Mobile Prefix Advertisement")]
    MobilePrefixAdvertisement = 147,
    #[strum(to_string = "Duplicate Address Request")]
    DuplicateAddressRequest = 157,
    #[strum(to_string = "Duplicate Address Confirmation")]
    DuplicateAddressConfirmation = 158,
    #[strum(to_string = "Extended Echo Request")]
    ExtendedEchoRequest = 160,
    #[strum(to_string = "Extended Echo Reply")]
    ExtendedEchoReply = 161,
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::DestinationUnreachable,
            2 => Self::PacketTooBig,
            3 => Self::TimeExceeded,
            4 => Self::ParameterProblem,
            128 => Self::EchoRequest,
            129 => Self::EchoReply,
            130 => Self::MulticastListenerQuery,
            131 => Self::MulticastListenerReport,
            132 => Self::MulticastListenerDone,
            133 => Self::RouterSolicitation,
            134 => Self::RouterAdvertisement,
            135 => Self::NeighborSolicitation,
            136 => Self::NeighborAdvertisement,
            137 => Self::RedirectMessage,
            138 => Self::RouterRenumbering,
            139 => Self::ICMPNodeInformationQuery,
            140 => Self::ICMPNodeInformationResponse,
            141 => Self::InverseNeighborDiscoverySolicitation,
            142 => Self::InverseNeighborDiscoveryAdvertisement,
            144 => Self::HomeAgentAddressDiscoveryRequest,
            145 => Self::HomeAgentAddressDiscoveryReply,
            146 => Self::MobilePrefixSolicitation,
            147 => Self::MobilePrefixAdvertisement,
            157 => Self::DuplicateAddressRequest,
            158 => Self::DuplicateAddressConfirmation,
            160 => Self::ExtendedEchoRequest,
            161 => Self::ExtendedEchoReply,
            _ => Self::Reserved,
        }
    }
}
