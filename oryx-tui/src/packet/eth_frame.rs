use core::fmt::Display;

use network_types::eth::{EthHdr, EtherType};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
    Frame,
};

use super::link::MacAddr;

pub struct EthFrameHeader {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub ether_type: EtherTypeWrapper,
}

pub struct EtherTypeWrapper(pub EtherType);

impl From<EthHdr> for EthFrameHeader {
    fn from(value: EthHdr) -> Self {
        Self {
            src: MacAddr(value.src_addr),
            dst: MacAddr(value.dst_addr),
            ether_type: EtherTypeWrapper(value.ether_type),
        }
    }
}

impl EthFrameHeader {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Fill(1)])
            .split(block)[0];

        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .horizontal_margin(4)
                .split(block);

            (chunks[0], chunks[1])
        };

        let title = Paragraph::new("Ethernet")
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
                Span::styled("Dest MAC Address", Style::new().bold()),
                Span::from(self.dst.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Source MAC Address", Style::new().bold()),
                Span::from(self.src.to_string()),
            ]),
        ];
        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().light_blue())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

impl Display for EthFrameHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {} {} EthFrameHeader",
            self.src, self.dst, self.ether_type
        )
    }
}

impl Display for EtherTypeWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            EtherType::Loop => write!(f, "Loop"),
            EtherType::Ipv4 => write!(f, "Ipv4"),
            EtherType::Arp => write!(f, "Arp"),
            EtherType::Ipv6 => write!(f, "Ipv6"),
            EtherType::FibreChannel => write!(f, "FibreChannel"),
            EtherType::Infiniband => write!(f, "Infiniband"),
            EtherType::LoopbackIeee8023 => write!(f, "LoopbackIeee8023"),
        }
    }
}
