use core::net::Ipv4Addr;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};

use crate::packet::network::ip::IpProto;

#[derive(Debug, Copy, Clone)]
pub struct Ipv4Packet {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: IpProto,
    pub checksum: u16,
}

impl Ipv4Packet {
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
        let title = Paragraph::new("IPv4")
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
                Span::styled("Internet Header Length", Style::new().bold()),
                Span::from(format!("{} bytes", self.ihl)),
            ]),
            Row::new(vec![
                Span::styled("Type Of Service", Style::new().bold()),
                Span::from(self.tos.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Total Length", Style::new().bold()),
                Span::from(format!("{} bytes", self.total_length)),
            ]),
            Row::new(vec![
                Span::styled("ID", Style::new().bold()),
                Span::from(self.id.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Fragment Offset", Style::new().bold()),
                Span::from(self.fragment_offset.to_string()),
            ]),
            Row::new(vec![
                Span::styled("TTL", Style::new().bold()),
                Span::from(self.ttl.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
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
