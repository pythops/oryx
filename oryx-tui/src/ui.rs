use ratatui::Frame;

use crate::app::{ActivePopup, App};

pub fn render(app: &mut App, frame: &mut Frame) {
    app.render(frame);

    if let Some(popup) = &app.active_popup {
        match popup {
            ActivePopup::Help => app.help.render(frame),
            ActivePopup::PacketInfos => app.section.inspection.render_packet_infos_popup(frame),
            ActivePopup::UpdateFilters => app.filter.render_update_popup(frame),
        }
    }
    for (index, notification) in app.notifications.iter().enumerate() {
        notification.render(index, frame);
    }
}
