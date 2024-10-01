use ratatui::Frame;

use crate::app::{ActivePopup, App};

pub fn render(app: &mut App, frame: &mut Frame) {
    app.render(frame);

    if let Some(popup) = &app.active_popup {
        match popup {
            ActivePopup::Help => app.help.render(frame),
            ActivePopup::PacketInfos => app.render_packet_infos_popup(frame),
            _ => {}
        }
    }
    for (index, notification) in app.notifications.iter().enumerate() {
        notification.render(index, frame);
    }
}
