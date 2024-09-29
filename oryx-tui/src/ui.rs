use ratatui::Frame;

use crate::app::App;

pub fn render(app: &mut App, frame: &mut Frame) {
    // match app.focused_block.clone() {
    //     FocusedBlock::StartMenuBlock(b) => b.render(frame, app),
    //     FocusedBlock::Main(section) => render_main_section(app, frame, &section),
    //     _ => {
    //         match app.previous_focused_block.clone() {
    //             FocusedBlock::StartMenuBlock(b) => b.render(frame, app),
    //             FocusedBlock::Main(section) => render_main_section(app, frame, &section),
    //             _ => {}
    //         }
    //         match app.focused_block {
    //             FocusedBlock::UpdateFilterMenuBlock(b) => b.render(frame, app),
    //             FocusedBlock::Help => app.help.render(frame),
    //             _ => {}
    //         }
    //     }
    // }
    app.phase.clone().render(frame, frame.area(), app);

    for (index, notification) in app.notifications.iter().enumerate() {
        notification.render(index, frame);
    }
}
