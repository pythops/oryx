use std::{collections::HashMap, net::IpAddr};

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Flex, Rect},
    style::{Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Row, Table},
};

use crate::section::alert::Threat;

#[derive(Debug)]
pub struct SynFlood {
    pub map: HashMap<IpAddr, usize>,
}

impl Threat for SynFlood {}

impl ratatui::widgets::WidgetRef for SynFlood {
    fn render_ref(&self, area: Rect, buf: &mut Buffer) {
        let mut ips: Vec<(IpAddr, usize)> = { self.map.clone().into_iter().collect() };

        ips.sort_by(|a, b| b.1.cmp(&a.1));

        ips.retain(|(_, count)| *count > 10_000);

        let top_3_ips = ips.into_iter().take(3);

        let widths = [Constraint::Min(30), Constraint::Min(20)];

        let rows = top_3_ips.map(|(ip, count)| {
            Row::new(vec![
                Line::from(ip.to_string()).centered().bold(),
                Line::from(count.to_string()).centered(),
            ])
        });
        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .header(
                Row::new(vec![
                    Line::from("IP Address").centered(),
                    Line::from("Number of SYN packets").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .block(
                Block::new()
                    .title(" SYN Flood Attack ")
                    .borders(Borders::all())
                    .border_style(Style::new().yellow())
                    .title_alignment(Alignment::Center),
            );

        table.render_ref(area, buf);
    }
}
