use libc::{AF_INET, AF_INET6, IFF_UP};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Row, Table, TableState},
    Frame,
};

use std::{
    ffi::CStr,
    fs::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub is_up: bool,
    pub addresses: Vec<IpAddr>,
    pub mac_address: Option<String>,
}

impl NetworkInterface {
    pub fn list() -> Vec<NetworkInterface> {
        let mut interfaces: Vec<NetworkInterface> = vec![];
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

            if libc::getifaddrs(&mut ifap) == 0 {
                let mut ifa = ifap;

                while !ifa.is_null() {
                    let ifa_name = (*ifa).ifa_name;
                    let ifa_addr = (*ifa).ifa_addr;
                    let ifa_flags = (*ifa).ifa_flags;

                    if !ifa_name.is_null() && !ifa_addr.is_null() {
                        let cstr_name = CStr::from_ptr(ifa_name);
                        let interface_name = cstr_name.to_str().unwrap();

                        let interface_path = PathBuf::from("/sys/class/net")
                            .join(interface_name)
                            .join("address");
                        let mac_address = fs::read_to_string(interface_path).ok();

                        if !interfaces.iter().any(|i| i.name == interface_name) {
                            interfaces.push(NetworkInterface {
                                name: interface_name.to_string(),
                                addresses: Vec::new(),
                                is_up: (ifa_flags as i32 & IFF_UP) != 0,
                                mac_address,
                            });
                        }

                        match (*ifa_addr).sa_family as i32 {
                            AF_INET => {
                                let sockaddr_in = ifa_addr as *const libc::sockaddr_in;
                                let ip_addr = (*sockaddr_in).sin_addr;

                                let ipv4_addr = IpAddr::V4(Ipv4Addr::from(ip_addr.s_addr.to_be()));

                                if let Some(index) =
                                    interfaces.iter_mut().position(|i| i.name == interface_name)
                                {
                                    interfaces[index].addresses.push(ipv4_addr);
                                }
                            }
                            AF_INET6 => {
                                let sockaddr_in = ifa_addr as *const libc::sockaddr_in6;
                                let ip_addr = (*sockaddr_in).sin6_addr;

                                let ipv6_addr = IpAddr::V6(Ipv6Addr::from(ip_addr.s6_addr));

                                if let Some(index) =
                                    interfaces.iter_mut().position(|i| i.name == interface_name)
                                {
                                    interfaces[index].addresses.push(ipv6_addr);
                                }
                            }
                            _ => {}
                        }
                    }

                    ifa = (*ifa).ifa_next;
                }

                libc::freeifaddrs(ifap);
            }
        }

        interfaces
    }
}

#[derive(Debug)]
pub struct Interface {
    pub interfaces: Vec<NetworkInterface>,
    pub selected_interface: NetworkInterface,
    pub state: TableState,
}

impl Default for Interface {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface {
    pub fn new() -> Self {
        let interfaces = NetworkInterface::list();
        let selected_interface = interfaces[0].clone();

        Self {
            interfaces,
            selected_interface,
            state: TableState::default().with_selected(0),
        }
    }

    pub fn scroll_down(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i < self.interfaces.len() - 1 {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
    }
    pub fn scroll_up(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i > 1 {
                    i - 1
                } else {
                    0
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
    }

    pub fn render_on_setup(&mut self, frame: &mut Frame, block: Rect, is_focused: bool) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(55),
                Constraint::Fill(1),
            ])
            .flex(Flex::Center)
            .split(block);

        let area = layout[1];

        let widths = [
            Constraint::Length(2),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Fill(1),
        ];

        let interfaces: Vec<Row> = self
            .interfaces
            .iter()
            .map(|interface| {
                let addr = {
                    match interface
                        .addresses
                        .iter()
                        .find(|a| matches!(a, IpAddr::V4(_) | IpAddr::V6(_)))
                    {
                        Some(a) => a.to_string(),
                        None => String::new(),
                    }
                };

                let state = if interface.is_up { "Up" } else { "Down" };

                Row::new(if self.selected_interface.name == interface.name {
                    vec![
                        Line::from(" "),
                        Line::from(interface.name.clone()),
                        Line::from(state.to_string()).centered(),
                        Line::from(addr.clone()),
                    ]
                } else {
                    vec![
                        Line::from(""),
                        Line::from(interface.name.clone()),
                        Line::from(state.to_string()).centered(),
                        Line::from(addr.clone()),
                    ]
                })
            })
            .collect();

        let table = Table::new(interfaces, widths)
            .header(
                Row::new(vec!["", "Name", "State", "Address"])
                    .style(Style::new().bold())
                    .bottom_margin(1),
            )
            .row_highlight_style(Style::new().bg(ratatui::style::Color::DarkGray))
            .column_spacing(3);

        frame.render_widget(
            Block::new()
                .title(" Interfaces   ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if is_focused {
                    BorderType::Thick
                } else {
                    BorderType::default()
                })
                .border_style(Style::default().fg(Color::Green)),
            area,
        );

        frame.render_stateful_widget(
            table,
            area.inner(ratatui::layout::Margin {
                horizontal: 5,
                vertical: 2,
            }),
            &mut self.state,
        );
    }

    pub fn render_on_sniffing(&mut self, frame: &mut Frame, block: Rect) {
        let widths = [Constraint::Length(4), Constraint::Fill(1)];

        let interface_infos = [
            Row::new(vec![
                Span::styled("Name", Style::new().bold()),
                Span::from(self.selected_interface.name.clone()),
            ]),
            Row::new(vec![
                Span::styled("Mac", Style::new().bold()),
                Span::from(
                    self.selected_interface
                        .mac_address
                        .clone()
                        .unwrap_or("-".to_string()),
                ),
            ]),
            Row::new(vec![
                Span::styled("IPv4", Style::new().bold()),
                Span::from(
                    self.selected_interface
                        .addresses
                        .iter()
                        .find(|a| matches!(a, IpAddr::V4(_) | IpAddr::V6(_)))
                        .unwrap()
                        .to_string(),
                ),
            ]),
            Row::new(vec![
                Span::styled("IPv6", Style::new().bold()),
                Span::from({
                    match self
                        .selected_interface
                        .addresses
                        .iter()
                        .find(|a| matches!(a, IpAddr::V6(_)))
                    {
                        Some(ip) => ip.to_string(),
                        None => "-".to_string(),
                    }
                }),
            ]),
        ];

        let table = Table::new(interface_infos, widths).column_spacing(3).block(
            Block::default()
                .title(" Interface 󰲝 ")
                .title_style(Style::default().bold().green())
                .title_alignment(Alignment::Center)
                .padding(Padding::horizontal(2))
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::default())
                .border_style(Style::default().green()),
        );
        frame.render_widget(table, block);
    }
}
