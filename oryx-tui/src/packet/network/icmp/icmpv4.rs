use core::fmt::Display;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};

#[derive(Debug, Copy, Clone)]
pub struct Icmpv4Packet {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
}

impl Icmpv4Packet {
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

#[derive(Debug, Copy, Clone)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    RedirectMessage,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    BadIPheader,
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply,
    Deprecated,
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            5 => IcmpType::RedirectMessage,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::BadIPheader,
            13 => IcmpType::Timestamp,
            14 => IcmpType::TimestampReply,
            42 => IcmpType::ExtendedEchoRequest,
            43 => IcmpType::ExtendedEchoReply,
            _ => IcmpType::Deprecated,
        }
    }
}

impl Display for IcmpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IcmpType::EchoReply => {
                write!(f, "Echo Reply")
            }
            IcmpType::EchoRequest => {
                write!(f, "Echo Request")
            }
            IcmpType::DestinationUnreachable => {
                write!(f, "Destination Unreachable")
            }
            IcmpType::RedirectMessage => {
                write!(f, "Redirect Message")
            }
            IcmpType::RouterAdvertisement => {
                write!(f, "Router Advertisement")
            }
            IcmpType::RouterSolicitation => {
                write!(f, "Router Solicitation")
            }
            IcmpType::TimeExceeded => {
                write!(f, "Time Exceeded")
            }
            IcmpType::BadIPheader => {
                write!(f, "Bad IP header")
            }
            IcmpType::Timestamp => {
                write!(f, "Timestamp")
            }
            IcmpType::TimestampReply => {
                write!(f, "Timestamp Reply")
            }
            IcmpType::ExtendedEchoRequest => {
                write!(f, "Extended Echo Request")
            }
            IcmpType::ExtendedEchoReply => {
                write!(f, "Extended Echo Reply")
            }
            IcmpType::Deprecated => {
                write!(f, "Deprecated")
            }
        }
    }
}
