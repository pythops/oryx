use core::net::Ipv6Addr;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};

use crate::packet::network::ip::IpProto;

#[derive(Debug, Copy, Clone)]
pub struct Ipv6Packet {
    pub ds: u8,
    pub ecn: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub proto: IpProto,
}

impl Ipv6Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        // Title
        let title = Paragraph::new("IPv6")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height.is_multiple_of(2) {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));

        // IP
        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source IP", Style::new().bold()),
                Span::from(self.src_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination IP", Style::new().bold()),
                Span::from(self.dst_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Differentiated services ", Style::new().bold()),
                Span::from(self.ds.to_string()),
            ]),
            Row::new(vec![
                Span::styled("ECN", Style::new().bold()),
                Span::from(self.ecn.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Flow Label", Style::new().bold()),
                Span::from(format!("{:#0x}", self.flow_label)),
            ]),
            Row::new(vec![
                Span::styled("Payload Length", Style::new().bold()),
                Span::from(self.payload_length.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hop Limit", Style::new().bold()),
                Span::from(self.hop_limit.to_string()),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().magenta())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );

        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}
