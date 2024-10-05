use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Flex, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Clear, HighlightSpacing, Padding, Row, Table, TableState},
    Frame,
};
use std::{net::IpAddr, str::FromStr};
use tui_input::{backend::crossterm::EventHandler, Input};

#[derive(Debug, Clone)]
pub struct FirewallRule {
    name: String,
    enabled: bool,
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FocusedInput {
    Name,
    Ip,
    Port,
}

#[derive(Debug, Clone)]
struct UserInput {
    pub name: UserInputField,
    pub ip: UserInputField,
    pub port: UserInputField,
    focus_input: FocusedInput,
}

#[derive(Debug, Clone, Default)]
struct UserInputField {
    field: Input,
    error: String,
}

impl UserInput {
    pub fn new() -> Self {
        Self {
            name: UserInputField::default(),
            ip: UserInputField::default(),
            port: UserInputField::default(),
            focus_input: FocusedInput::Name,
        }
    }

    fn validate_name(&mut self) {
        self.name.error.clear();
        if self.name.field.value().is_empty() {
            self.name.error = "Required field.".to_string();
        }
    }

    fn validate_ip(&mut self) {
        self.ip.error.clear();
        if self.ip.field.value().is_empty() {
            self.ip.error = "Required field.".to_string();
        } else if IpAddr::from_str(self.ip.field.value()).is_err() {
            self.ip.error = "Invalid IP Address.".to_string();
        }
    }

    fn validate_port(&mut self) {
        self.port.error.clear();
        if self.port.field.value().is_empty() {
            self.port.error = "Required field.".to_string();
        } else if u16::from_str(self.port.field.value()).is_err() {
            self.port.error = "Invalid Port number.".to_string();
        }
    }

    fn validate(&mut self) {
        self.validate_name();
        self.validate_ip();
        self.validate_port();
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
                    .fg(Color::White),
                Cell::from(self.ip.field.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Ip {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::White),
                Cell::from(self.port.field.to_string())
                    .bg({
                        if self.focus_input == FocusedInput::Port {
                            Color::Gray
                        } else {
                            Color::DarkGray
                        }
                    })
                    .fg(Color::White),
            ]),
            Row::new(vec![Cell::new(""), Cell::new(""), Cell::new("")]),
            Row::new(vec![
                Cell::from(self.name.clone().error).red(),
                Cell::from(self.ip.clone().error).red(),
                Cell::from(self.port.clone().error).red(),
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
                    .title(" New Firewall Rule ")
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

#[derive(Debug, Clone, Default)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    state: TableState,
    user_input: Option<UserInput>,
}

impl Firewall {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            state: TableState::default(),
            user_input: None,
        }
    }

    pub fn add_rule(&mut self) {
        self.user_input = Some(UserInput::new());
    }

    pub fn remove_rule(&mut self, rule: &FirewallRule) {
        self.rules.retain(|r| r.name != rule.name);
    }

    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        if let Some(user_input) = &mut self.user_input {
            match key_event.code {
                KeyCode::Esc => {
                    self.user_input = None;
                }

                KeyCode::Enter => {
                    if let Some(user_input) = &mut self.user_input {
                        user_input.validate();
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
    }

    pub fn render(&self, frame: &mut Frame, block: Rect) {
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
            Constraint::Length(10),
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

        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceAround)
            .highlight_style(Style::default().bg(Color::DarkGray))
            .header(
                Row::new(vec![
                    Line::from("Name").centered(),
                    Line::from("IP").centered(),
                    Line::from("Port").centered(),
                    Line::from("Status").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            );

        frame.render_widget(
            table,
            block.inner(Margin {
                horizontal: 2,
                vertical: 2,
            }),
        );
    }

    pub fn render_new_rule_popup(&self, frame: &mut Frame) {
        if let Some(user_input) = &mut self.user_input.clone() {
            user_input.render(frame);
        }
    }
}
