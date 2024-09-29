use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Style, Stylize},
    widgets::{Block, BorderType, Borders, Clear},
    Frame,
};

use crate::app::App;

use super::packet::AppPacket;

pub struct PacketInfo {}
impl PacketInfo {
    pub fn render(frame: &mut Frame, app: &mut App) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(36),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Max(80),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        let fuzzy = app.fuzzy.lock().unwrap();
        let packets = app.packets.lock().unwrap();

        let packet = if fuzzy.is_enabled() {
            fuzzy.packets[app.packet_index.unwrap()]
        } else {
            packets[app.packet_index.unwrap()]
        };

        frame.render_widget(Clear, block);
        frame.render_widget(
            Block::new()
                .title(" Packet Infos 󰋼  ")
                .title_style(Style::new().bold().green())
                .title_alignment(Alignment::Center)
                .borders(Borders::all())
                .border_style(Style::new().green())
                .border_type(BorderType::Thick),
            block,
        );
        match packet {
            AppPacket::Ip(ip_packet) => ip_packet.render(block, frame),
            AppPacket::Arp(arp_packet) => arp_packet.render(block, frame),
        };
    }
    pub fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App) {
        match key_event.code {
            KeyCode::Esc => app.phase.popup = None,
            _ => {}
        }
    }
}
