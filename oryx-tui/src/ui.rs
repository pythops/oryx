use ratatui::Frame;

use crate::app::{App, FocusedBlock};

pub fn render(app: &mut App, frame: &mut Frame) {
    app.render(frame);

    if let FocusedBlock::Help = app.focused_block {
        app.help.render(frame);
    }

    for (index, notification) in app.notifications.iter().enumerate() {
        notification.render(index, frame);
    }
}
