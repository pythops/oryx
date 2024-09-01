use libc::{AF_INET, AF_INET6, IFF_UP};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Frame,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::ffi::CStr;

use crate::app::FocusedBlock;

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub is_up: bool,
    pub addresses: Vec<IpAddr>,
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

                        if !interfaces.iter().any(|i| i.name == interface_name) {
                            interfaces.push(NetworkInterface {
                                name: interface_name.to_string(),
                                addresses: Vec::new(),
                                is_up: (ifa_flags as i32 & IFF_UP) != 0,
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

    pub fn render(&mut self, frame: &mut Frame, block: Rect, focused_block: &FocusedBlock) {
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
            .highlight_style(Style::new().bg(ratatui::style::Color::DarkGray))
            .column_spacing(3);

        frame.render_widget(
            Block::new()
                .title(" Interfaces   ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::LEFT)
                .border_type(if *focused_block == FocusedBlock::Interface {
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
}
