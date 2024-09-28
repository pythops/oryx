use std::net::IpAddr;

use ratatui::{
    layout::{Alignment, Constraint, Flex, Rect},
    style::{Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Padding, Row, Table},
    Frame,
};

#[derive(Debug, Clone, Default)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    name: String,
    enabled: bool,
    ip: Option<IpAddr>,
    port: Option<u16>,
}

impl Firewall {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        if self.rules.iter().any(|r| r.name == rule.name) {
            return;
        }
        self.rules.push(rule);
    }
    pub fn remove_rule(&mut self, rule: &FirewallRule) {
        self.rules.retain(|r| r.name != rule.name);
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
        let widths = [
            Constraint::Min(30),
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(10),
        ];

        let rows = self.rules.iter().map(|rule| {
            Row::new(vec![
                Line::from(rule.name.clone()).centered().bold(),
                Line::from({
                    if let Some(ip) = rule.ip {
                        ip.to_string()
                    } else {
                        "-".to_string()
                    }
                })
                .centered()
                .bold(),
                Line::from({
                    if let Some(port) = rule.port {
                        port.to_string()
                    } else {
                        "-".to_string()
                    }
                })
                .centered(),
                Line::from(rule.enabled.to_string()).centered(),
            ])
        });
        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .header(
                Row::new(vec![
                    Line::from("Name").centered(),
                    Line::from("IP Address").centered(),
                    Line::from("Port").centered(),
                    Line::from("Enabled?").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .block(
                Block::new()
                    .title(" Firewall Rules ")
                    .borders(Borders::all())
                    .border_style(Style::new().yellow())
                    .title_alignment(Alignment::Center)
                    .padding(Padding::uniform(2)),
            );

        frame.render_widget(table, block);
    }
}
