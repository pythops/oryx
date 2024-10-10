use core::fmt::Display;
use crossterm::event::{Event, KeyCode, KeyEvent};
use log::{error, info};
use oryx_common::MAX_FIREWALL_RULES;
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Clear, HighlightSpacing, Padding, Row, Table, TableState},
    Frame,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{fs, net::IpAddr, num::ParseIntError, os::unix::fs::chown, str::FromStr};
use tui_input::{backend::crossterm::EventHandler, Input};
use uuid;

use crate::{app::AppResult, filter::direction::TrafficDirection, notification::Notification};

#[derive(Debug, Clone)]
pub enum FirewallSignal {
    Rule(FirewallRule),
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    id: uuid::Uuid,
    name: String,
    pub enabled: bool,
    pub ip: IpAddr,
    pub port: BlockedPort,
    direction: TrafficDirection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

// TODO: Add direction
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
    Direction,
}

#[derive(Debug, Clone)]
struct UserInput {
    id: Option<uuid::Uuid>,
    name: UserInputField,
    ip: UserInputField,
    port: UserInputField,
    direction: TrafficDirection,
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
            direction: TrafficDirection::Ingress,
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
                Constraint::Percentage(80),
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
                Cell::from(self.direction.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Direction {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::Black),
            ]),
            Row::new(vec![
                Cell::new(""),
                Cell::new(""),
                Cell::new(""),
                Cell::new(""),
            ]),
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
                Cell::new(""),
            ]),
        ];

        let widths = [
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    Line::from("Name").centered(),
                    Line::from("IP").centered(),
                    Line::from("Port").centered(),
                    Line::from("Direction").centered(),
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
                    .bold()
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
            direction: rule.direction,
            focus_input: FocusedInput::Name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    state: TableState,
    user_input: Option<UserInput>,
    ingress_sender: kanal::Sender<FirewallSignal>,
    egress_sender: kanal::Sender<FirewallSignal>,
}

impl Firewall {
    pub fn new(
        ingress_sender: kanal::Sender<FirewallSignal>,
        egress_sender: kanal::Sender<FirewallSignal>,
    ) -> Self {
        let rules_list: Vec<FirewallRule> = match Self::load_saved_rules() {
            Ok(saved_rules) => saved_rules,

            Err(err) => {
                error!("{}", err.to_string());
                Vec::new()
            }
        };
        Self {
            rules: rules_list,
            state: TableState::default(),
            user_input: None,
            ingress_sender,
            egress_sender,
        }
    }

    pub fn add_rule(&mut self) {
        self.user_input = Some(UserInput::new());
    }

    pub fn save_rules(&self) -> AppResult<()> {
        info!("Saving Firewall Rules");

        let json = serde_json::to_string(&self.rules)?;

        let user_uid = unsafe { libc::geteuid() };

        let oryx_export_dir = dirs::home_dir().unwrap().join("oryx");

        if !oryx_export_dir.exists() {
            fs::create_dir(&oryx_export_dir)?;
            chown(&oryx_export_dir, Some(user_uid), Some(user_uid))?;
        }

        let oryx_export_file = oryx_export_dir.join("firewall.json");
        fs::write(oryx_export_file, json)?;
        info!("Firewall Rules saved");

        Ok(())
    }

    fn load_saved_rules() -> AppResult<Vec<FirewallRule>> {
        let oryx_export_file = dirs::home_dir().unwrap().join("oryx").join("firewall.json");
        if oryx_export_file.exists() {
            info!("Loading Firewall Rules");

            let json_string = fs::read_to_string(oryx_export_file)?;

            let mut parsed_rules: Vec<FirewallRule> = serde_json::from_str(&json_string)?;

            // as we don't know if ingress/egress programs are loaded we have to disable all rules
            parsed_rules
                .iter_mut()
                .for_each(|rule| rule.enabled = false);

            info!("Firewall Rules loaded");
            Ok(parsed_rules)
        } else {
            info!("Firewall Rules file not found");
            Ok(Vec::new())
        }
    }

    fn validate_duplicate_rules(rules: &[FirewallRule], user_input: &UserInput) -> AppResult<()> {
        if let Some(exiting_rule_with_same_ip) = rules.iter().find(|rule| {
            rule.ip == IpAddr::from_str(user_input.ip.field.value()).unwrap()
                && rule.direction == user_input.direction
                && match user_input.id {
                    Some(uuid) => rule.id != uuid,
                    None => true,
                }
        }) {
            let new_port = BlockedPort::from_str(user_input.port.field.value()).unwrap();

            if exiting_rule_with_same_ip.port == new_port {
                return Err("Rule validation error".into());
            }

            match exiting_rule_with_same_ip.port {
                BlockedPort::Single(_) => {
                    if new_port == BlockedPort::All {
                        return Err("Rule validation error".into());
                    }
                }

                BlockedPort::All => {
                    return Err("Rule validation error".into());
                }
            }
        }

        Ok(())
    }

    pub fn remove_rule(&mut self, rule: &FirewallRule) {
        self.rules.retain(|r| r.name != rule.name);
    }

    pub fn disable_ingress_rules(&mut self) {
        self.rules.iter_mut().for_each(|rule| {
            if rule.enabled && rule.direction == TrafficDirection::Ingress {
                rule.enabled = false;
            }
        });
    }
    pub fn disable_egress_rules(&mut self) {
        self.rules.iter_mut().for_each(|rule| {
            if rule.enabled && rule.direction == TrafficDirection::Egress {
                rule.enabled = false;
            }
        });
    }

    pub fn submit_rule(
        &mut self,
        // sender: kanal::Sender<crate::event::Event>,
        // is_ingress_loaded: bool,
        // is_egress_loaded: bool,
    ) -> AppResult<()> {
        if let Some(index) = self.state.selected() {
            let rule = &mut self.rules[index];

            match rule.direction {
                TrafficDirection::Ingress => {
                    rule.enabled = !rule.enabled;
                    self.ingress_sender
                        .send(FirewallSignal::Rule(rule.clone()))?;
                }
                TrafficDirection::Egress => {
                    rule.enabled = !rule.enabled;
                    self.egress_sender
                        .send(FirewallSignal::Rule(rule.clone()))?;
                }
            }
        }
        Ok(())
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

                        if let Err(e) = Firewall::validate_duplicate_rules(&self.rules, user_input)
                        {
                            Notification::send(
                                "Duplicate Rule",
                                crate::notification::NotificationLevel::Warning,
                                sender.clone(),
                            )?;
                            return Err(e);
                        }

                        if let Some(id) = user_input.id {
                            let rule = self.rules.iter_mut().find(|rule| rule.id == id).unwrap();

                            rule.name = user_input.name.field.to_string();
                            rule.ip = IpAddr::from_str(user_input.ip.field.value()).unwrap();
                            rule.port =
                                BlockedPort::from_str(user_input.port.field.value()).unwrap();
                            rule.direction = user_input.direction;
                        } else {
                            let rule = FirewallRule {
                                id: uuid::Uuid::new_v4(),
                                name: user_input.name.field.to_string(),
                                ip: IpAddr::from_str(user_input.ip.field.value()).unwrap(),
                                port: BlockedPort::from_str(user_input.port.field.value()).unwrap(),
                                direction: user_input.direction,
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
                            FocusedInput::Port => user_input.focus_input = FocusedInput::Direction,
                            FocusedInput::Direction => user_input.focus_input = FocusedInput::Name,
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
                    FocusedInput::Direction => match key_event.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            user_input.direction = TrafficDirection::Ingress;
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            user_input.direction = TrafficDirection::Egress;
                        }
                        _ => {}
                    },
                },
            }
        } else {
            match key_event.code {
                KeyCode::Char('n') => {
                    if self.rules.len() == MAX_FIREWALL_RULES as usize {
                        Notification::send(
                            "Max rules reached",
                            crate::notification::NotificationLevel::Warning,
                            sender.clone(),
                        )?;
                        return Err("Can not edit enabled rule".into());
                    }
                    self.add_rule();
                }

                KeyCode::Char('s') => match self.save_rules() {
                    Ok(_) => {
                        Notification::send(
                            "Sync firewall rules to ~/oryx/firewall.json",
                            crate::notification::NotificationLevel::Info,
                            sender.clone(),
                        )?;
                    }
                    Err(e) => {
                        Notification::send(
                            "Error while syncing firewall rules",
                            crate::notification::NotificationLevel::Error,
                            sender.clone(),
                        )?;
                        error!("Error while syncing firewall rules. {}", e);
                    }
                },

                KeyCode::Char('e') => {
                    if let Some(index) = self.state.selected() {
                        let rule = self.rules[index].clone();
                        if rule.enabled {
                            Notification::send(
                                "Can not edit enabled rule",
                                crate::notification::NotificationLevel::Warning,
                                sender.clone(),
                            )?;
                            return Err("Can not edit enabled rule".into());
                        } else {
                            self.user_input = Some(rule.into());
                        }
                    }
                }

                KeyCode::Char('d') => {
                    if let Some(index) = self.state.selected() {
                        let rule = &mut self.rules[index];

                        rule.enabled = false;
                        match rule.direction {
                            TrafficDirection::Ingress => {
                                self.ingress_sender
                                    .send(FirewallSignal::Rule(rule.clone()))?;
                            }
                            TrafficDirection::Egress => self
                                .egress_sender
                                .send(FirewallSignal::Rule(rule.clone()))?,
                        }

                        self.rules.remove(index);
                    }
                }

                KeyCode::Char('j') | KeyCode::Down => {
                    if self.rules.is_empty() {
                        return Ok(());
                    }

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
                    if self.rules.is_empty() {
                        return Ok(());
                    }
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
            Constraint::Length(14),
        ];

        let rows = self.rules.iter().map(|rule| {
            Row::new(vec![
                Line::from(rule.name.clone()).centered().bold(),
                Line::from(rule.ip.to_string()).centered().bold(),
                Line::from(rule.port.to_string()).centered().bold(),
                Line::from({
                    match rule.direction {
                        TrafficDirection::Ingress => String::from("Ingress 󰁅  "),
                        TrafficDirection::Egress => String::from("Egress  "),
                    }
                })
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
                    Line::from("Direction").centered().blue(),
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
