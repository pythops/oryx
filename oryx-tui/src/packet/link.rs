use core::fmt::Display;
use std::net::Ipv4Addr;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
};

#[derive(Debug, Copy, Clone)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub arp_type: ArpType,
    pub src_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub dst_mac: MacAddr,
    pub dst_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let block = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(11), Constraint::Fill(1)])
            .flex(ratatui::layout::Flex::SpaceAround)
            .margin(1)
            .split(block)[0];

        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(1)
                .split(block);

            (chunks[0], chunks[1])
        };

        let title = Paragraph::new("ARP")
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
                Span::styled("Hardware Type", Style::new().bold()),
                Span::from(self.htype.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Protocol Type", Style::new().bold()),
                Span::from(self.ptype.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Hardware Length", Style::new().bold()),
                Span::from(self.hlen.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Protocol Length", Style::new().bold()),
                Span::from(self.plen.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Operation", Style::new().bold()),
                Span::from(self.arp_type.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sender hardware address", Style::new().bold()),
                Span::from(self.src_mac.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sender protocol address", Style::new().bold()),
                Span::from(self.src_ip.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target hardware address", Style::new().bold()),
                Span::from(self.dst_mac.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Target protocol address", Style::new().bold()),
                Span::from(self.dst_ip.to_string()),
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

impl Display for ArpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {} ARP", self.src_mac, self.dst_mac)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ArpType {
    Request,
    Reply,
}

impl Display for ArpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Request => write!(f, "Arp Request"),
            Self::Reply => write!(f, "Arp Reply"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MacAddr(pub [u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        //FIX: workaround for the moment
        if self.0.iter().all(|&x| x == 0x00) {
            write!(f, "ff:ff:ff:ff:ff:ff",)
        } else {
            write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0].to_be(),
                self.0[1].to_be(),
                self.0[2].to_be(),
                self.0[3].to_be(),
                self.0[4].to_be(),
                self.0[5].to_be()
            )
        }
    }
}
