use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};
use std::net::Ipv4Addr;

use crate::packet::network::igmp::IgmpType;

#[derive(Debug, Copy, Clone)]
pub struct IGMPv2Packet {
    pub igmp_type: IgmpType,
    pub max_response_time: u8,
    pub checksum: u16,
    pub group_address: Ipv4Addr,
}

impl IGMPv2Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("IGMPv2")
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
                Span::from(self.igmp_type.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Max Response time", Style::new().bold()),
                Span::from(self.max_response_time.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Group Address", Style::new().bold()),
                Span::from(self.group_address.to_string()),
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
