pub mod app;

pub mod event;

pub mod ui;

pub mod tui;

pub mod handler;

pub mod help;

pub mod interface;

pub mod ebpf;

pub mod filters {
    pub mod direction;
    pub mod filter;
    pub mod fuzzy;
    pub mod link;
    pub mod network;
    pub mod start_menu;
    pub mod transport;
    pub mod update_menu;
}

pub mod notification;

pub mod export;

pub mod stats;

pub mod bandwidth;

pub mod packets {
    pub mod link;
    pub mod network;
    pub mod packet;
    pub mod transport;
}

pub mod alerts {
    pub mod alert;
    pub mod syn_flood;
}

pub mod firewall;

pub mod mode;

pub trait MenuComponent {
    fn set_state(&mut self, value: Option<usize>);
    fn select(&mut self);
}
pub trait Scrollable {
    fn scroll_up(&mut self);
    fn scroll_down(&mut self);
}

pub trait ScrollableMenuComponent: MenuComponent + Scrollable {}

impl<T: MenuComponent + Scrollable> ScrollableMenuComponent for T {}
