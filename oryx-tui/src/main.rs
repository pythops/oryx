#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io;

use clap::{crate_description, crate_version, Command};
use oryx_tui::{
    app::{App, AppResult, TICK_RATE},
    event::{Event, EventHandler},
    handler::handle_key_events,
    tui::Tui,
};
use ratatui::{backend::CrosstermBackend, Terminal};

fn main() -> AppResult<()> {
    env_logger::init();
    Command::new("oryx")
        .about(crate_description!())
        .version(crate_version!())
        .get_matches();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program must be run as root");
        std::process::exit(1);
    }

    let mut app = App::new();

    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(TICK_RATE);
    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    while app.running {
        tui.draw(&mut app)?;
        match tui.events.next()? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => {
                handle_key_events(key_event, &mut app, tui.events.sender.clone())?
            }
            Event::Notification(notification) => {
                app.notifications.push(notification);
            }
            Event::Reset => {
                app = App::new();
            }
            _ => {}
        }
    }

    tui.exit()?;
    Ok(())
}
