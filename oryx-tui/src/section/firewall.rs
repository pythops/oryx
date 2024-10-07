use core::fmt::Display;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Clear, HighlightSpacing, Padding, Row, Table, TableState},
    Frame,
};
use std::{net::IpAddr, num::ParseIntError, str::FromStr};
use tui_input::{backend::crossterm::EventHandler, Input};
use uuid;

use crate::{app::AppResult, notification::Notification};

#[derive(Debug, Clone)]
pub struct FirewallRule {
    id: uuid::Uuid,
    name: String,
    pub enabled: bool,
    pub ip: IpAddr,
    pub port: BlockedPort,
}

#[derive(Debug, Clone)]
pub enum BlockedPort {
    Single(u16),
    All,
}

impl Display for BlockedPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockedPort::Single(p) => write!(f, "{}", p),
            BlockedPort::All => write!(f, "*"),
        }
    }
}

impl FromStr for BlockedPort {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            Ok(BlockedPort::All)
        } else {
            Ok(BlockedPort::Single(u16::from_str(s)?))
        }
    }
}

impl Display for FirewallRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.ip, self.port)
    }
}
#[derive(Debug, Clone, PartialEq)]
pub enum FocusedInput {
    Name,
    Ip,
    Port,
}

#[derive(Debug, Clone)]
struct UserInput {
    id: Option<uuid::Uuid>,
    pub name: UserInputField,
    pub ip: UserInputField,
    pub port: UserInputField,
    focus_input: FocusedInput,
}

#[derive(Debug, Clone, Default)]
struct UserInputField {
    field: Input,
    error: Option<String>,
}

impl UserInput {
    pub fn new() -> Self {
        Self {
            id: None,
            name: UserInputField::default(),
            ip: UserInputField::default(),
            port: UserInputField::default(),
            focus_input: FocusedInput::Name,
        }
    }

    fn validate_name(&mut self) {
        self.name.error = None;
        if self.name.field.value().is_empty() {
            self.name.error = Some("Required field.".to_string());
        }
    }

    fn validate_ip(&mut self) {
        self.ip.error = None;
        if self.ip.field.value().is_empty() {
            self.ip.error = Some("Required field.".to_string());
        } else if IpAddr::from_str(self.ip.field.value()).is_err() {
            self.ip.error = Some("Invalid IP Address.".to_string());
        }
    }

    fn validate_port(&mut self) {
        self.port.error = None;
        if self.port.field.value().is_empty() {
            self.port.error = Some("Required field.".to_string());
        } else if BlockedPort::from_str(self.port.field.value()).is_err() {
            self.port.error = Some("Invalid Port number.".to_string());
        }
    }

    fn validate(&mut self) -> AppResult<()> {
        self.validate_name();
        self.validate_ip();
        self.validate_port();

        if self.name.error.is_some() || self.ip.error.is_some() || self.port.error.is_some() {
            return Err("Valdidation Error".into());
        }
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(9),
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

        let rows = [
            Row::new(vec![
                Cell::from(self.name.field.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Name {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::Black),
                Cell::from(self.ip.field.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Ip {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::Black),
                Cell::from(self.port.field.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Port {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::Black),
            ]),
            Row::new(vec![Cell::new(""), Cell::new(""), Cell::new("")]),
            Row::new(vec![
                Cell::from({
                    if let Some(error) = &self.name.error {
                        error.to_string()
                    } else {
                        String::new()
                    }
                })
                .red(),
                Cell::from({
                    if let Some(error) = &self.ip.error {
                        error.to_string()
                    } else {
                        String::new()
                    }
                })
                .red(),
                Cell::from({
                    if let Some(error) = &self.port.error {
                        error.to_string()
                    } else {
                        String::new()
                    }
                })
                .red(),
            ]),
        ];

        let widths = [
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    Line::from("Name").centered(),
                    Line::from("IP").centered(),
                    Line::from("Port").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .highlight_spacing(HighlightSpacing::Always)
            .block(
                Block::default()
                    .title(" Firewall Rule ")
                    .title_alignment(ratatui::layout::Alignment::Center)
                    .borders(Borders::all())
                    .border_type(ratatui::widgets::BorderType::Thick)
                    .border_style(Style::default().green())
                    .padding(Padding::uniform(1)),
            );

        frame.render_widget(Clear, block);
        frame.render_widget(table, block);
    }
}

impl From<FirewallRule> for UserInput {
    fn from(rule: FirewallRule) -> Self {
        Self {
            id: Some(rule.id),
            name: UserInputField {
                field: Input::from(rule.name),
                error: None,
            },
            ip: UserInputField {
                field: Input::from(rule.ip.to_string()),
                error: None,
            },
            port: UserInputField {
                field: Input::from(rule.port.to_string()),
                error: None,
            },
            focus_input: FocusedInput::Name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    state: TableState,
    user_input: Option<UserInput>,
    ingress_sender: kanal::Sender<FirewallRule>,
}

impl Firewall {
    pub fn new(ingress_sender: kanal::Sender<FirewallRule>) -> Self {
        Self {
            rules: Vec::new(),
            state: TableState::default(),
            user_input: None,
            ingress_sender,
        }
    }

    pub fn add_rule(&mut self) {
        self.user_input = Some(UserInput::new());
    }

    pub fn remove_rule(&mut self, rule: &FirewallRule) {
        self.rules.retain(|r| r.name != rule.name);
    }

    pub fn handle_keys(
        &mut self,
        key_event: KeyEvent,
        sender: kanal::Sender<crate::event::Event>,
    ) -> AppResult<()> {
        if let Some(user_input) = &mut self.user_input {
            match key_event.code {
                KeyCode::Esc => {
                    self.user_input = None;
                }

                KeyCode::Enter => {
                    if let Some(user_input) = &mut self.user_input {
                        user_input.validate()?;

                        if let Some(id) = user_input.id {
                            let rule = self.rules.iter_mut().find(|rule| rule.id == id).unwrap();
                            rule.name = user_input.name.field.to_string();
                            rule.ip = IpAddr::from_str(user_input.ip.field.value()).unwrap();
                            rule.port =
                                BlockedPort::from_str(user_input.port.field.value()).unwrap();
                        } else {
                            let rule = FirewallRule {
                                id: uuid::Uuid::new_v4(),
                                name: user_input.name.field.to_string(),
                                ip: IpAddr::from_str(user_input.ip.field.value()).unwrap(),
                                port: BlockedPort::from_str(user_input.port.field.value()).unwrap(),
                                enabled: false,
                            };
                            self.rules.push(rule);
                        }
                        self.user_input = None;
                    }
                }

                KeyCode::Tab => {
                    if let Some(user_input) = &mut self.user_input {
                        match user_input.focus_input {
                            FocusedInput::Name => user_input.focus_input = FocusedInput::Ip,
                            FocusedInput::Ip => user_input.focus_input = FocusedInput::Port,
                            FocusedInput::Port => user_input.focus_input = FocusedInput::Name,
                        }
                    }
                }

                _ => match user_input.focus_input {
                    FocusedInput::Name => {
                        user_input.name.field.handle_event(&Event::Key(key_event));
                    }
                    FocusedInput::Ip => {
                        user_input.ip.field.handle_event(&Event::Key(key_event));
                    }
                    FocusedInput::Port => {
                        user_input.port.field.handle_event(&Event::Key(key_event));
                    }
                },
            }
        } else {
            match key_event.code {
                KeyCode::Char('n') => {
                    self.add_rule();
                }

                KeyCode::Char(' ') => {
                    if let Some(index) = self.state.selected() {
                        self.rules[index].enabled = !self.rules[index].enabled;
                        self.ingress_sender.send(self.rules[index].clone())?
                    }
                }

                KeyCode::Char('e') => {
                    if let Some(index) = self.state.selected() {
                        let rule = self.rules[index].clone();
                        if rule.enabled {
                            Notification::send(
                                "Can not edit enabled rule",
                                crate::notification::NotificationLevel::Warning,
                                sender.clone(),
                            )?;
                        } else {
                            self.user_input = Some(rule.into());
                        }
                    }
                }

                KeyCode::Char('d') => {
                    if let Some(index) = self.state.selected() {
                        self.rules[index].enabled = false;
                        self.ingress_sender.send(self.rules[index].clone())?;
                        self.rules.remove(index);
                    }
                }

                KeyCode::Char('j') | KeyCode::Down => {
                    let i = match self.state.selected() {
                        Some(i) => {
                            if i < self.rules.len() - 1 {
                                i + 1
                            } else {
                                i
                            }
                        }
                        None => 0,
                    };

                    self.state.select(Some(i));
                }

                KeyCode::Char('k') | KeyCode::Up => {
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
                _ => {}
            }
        }

        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame, block: Rect) {
        if self.rules.is_empty() {
            let text_block = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Fill(1),
                    Constraint::Length(3),
                    Constraint::Fill(1),
                ])
                .flex(ratatui::layout::Flex::SpaceBetween)
                .margin(2)
                .split(block)[1];

            let text = Text::from("No Rules").bold().centered();
            frame.render_widget(text, text_block);
            return;
        }

        let widths = [
            Constraint::Max(30),
            Constraint::Max(20),
            Constraint::Length(10),
            Constraint::Length(14),
        ];

        let rows = self.rules.iter().map(|rule| {
            Row::new(vec![
                Line::from(rule.name.clone()).centered().bold(),
                Line::from(rule.ip.to_string()).centered().centered().bold(),
                Line::from(rule.port.to_string())
                    .centered()
                    .centered()
                    .bold(),
                Line::from({
                    if rule.enabled {
                        "Enabled".to_string()
                    } else {
                        "Disabled".to_string()
                    }
                })
                .centered()
                .centered()
                .bold(),
            ])
        });

        if self.state.selected().is_none() && !self.rules.is_empty() {
            self.state.select(Some(0));
        }

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .highlight_style(Style::default().bg(Color::DarkGray))
            .header(
                Row::new(vec![
                    Line::from("Name").centered().blue(),
                    Line::from("IP").centered().blue(),
                    Line::from("Port").centered().blue(),
                    Line::from("Status").centered().blue(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            );

        frame.render_stateful_widget(
            table,
            block.inner(Margin {
                horizontal: 2,
                vertical: 2,
            }),
            &mut self.state,
        );
    }

    pub fn render_new_rule_popup(&self, frame: &mut Frame) {
        if let Some(user_input) = &mut self.user_input.clone() {
            user_input.render(frame);
        }
    }
}
