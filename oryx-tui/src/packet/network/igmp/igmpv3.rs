use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};
use std::net::Ipv4Addr;

#[derive(Debug, Copy, Clone)]
pub enum IGMPv3Packet {
    Report(IGMPv3MembershipReportPacket),
    Query(IGMPv3MembershipQueryPacket),
}

impl IGMPv3Packet {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        match self {
            IGMPv3Packet::Report(packet) => {
                packet.render(block, frame);
            }
            IGMPv3Packet::Query(packet) => {
                packet.render(block, frame);
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IGMPv3MembershipReportPacket {
    pub checksum: u16,
    pub nb_group_records: u16,
}

#[derive(Debug, Copy, Clone)]
pub struct IGMPv3MembershipQueryPacket {
    pub max_response_code: u8,
    pub checksum: u16,
    pub group_address: Ipv4Addr,
    pub s: u8,
    pub qrv: u8,
    pub qqic: u8,
    pub nb_source_addr: u16,
}

impl IGMPv3MembershipQueryPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("IGMPv3")
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
                Span::from("IGMPv3 Membership Query"),
            ]),
            Row::new(vec![
                Span::styled("Max Response time", Style::new().bold()),
                Span::from(self.max_response_code.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Group Address", Style::new().bold()),
                Span::from(self.group_address.to_string()),
            ]),
            Row::new(vec![
                Span::styled("S", Style::new().bold()),
                Span::from(self.s.to_string()),
            ]),
            Row::new(vec![
                Span::styled("QRV", Style::new().bold()),
                Span::from(self.qrv.to_string()),
            ]),
            Row::new(vec![
                Span::styled("QQIC", Style::new().bold()),
                Span::from(self.qqic.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Number of Sources", Style::new().bold()),
                Span::from(self.nb_source_addr.to_string()),
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

impl IGMPv3MembershipReportPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("IGMPv3")
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
                Span::from("IGMPv3 Membership Report"),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Number Group Records", Style::new().bold()),
                Span::from(self.nb_group_records.to_string()),
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
