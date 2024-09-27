use std::net::IpAddr;

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Padding},
    Frame,
};

#[derive(Debug, Clone, Default)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    enabled: bool,
    ip: Option<IpAddr>,
    port: Option<u16>,
}

impl Firewall {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {}
    pub fn remove_rule(&mut self, rule: &FirewallRule) {}
    pub fn update_rule(&mut self) {}

    pub fn render(&self, frame: &mut Frame, block: Rect) {}
}
