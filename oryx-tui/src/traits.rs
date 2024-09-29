use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

use crate::app::App;

pub trait MenuComponent {
    fn set_state(&mut self, value: Option<usize>);
    fn select(&mut self);
}

pub trait Scrollable {
    fn scroll_up(&mut self);
    fn scroll_down(&mut self);
}

pub trait AppComponent {
    fn render(&self, frame: &mut Frame, area: Rect, app: &mut App)
    where
        Self: Sized;
    fn handle_key_events(&mut self, key_event: KeyEvent, app: &mut App)
    where
        Self: Sized;
}

pub trait ScrollableMenuComponent: MenuComponent + Scrollable {}

impl<T: MenuComponent + Scrollable> ScrollableMenuComponent for T {}
