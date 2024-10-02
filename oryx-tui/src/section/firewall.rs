use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Constraint, Flex, Rect},
    style::{Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Padding, Row, Table},
    Frame,
};
use std::net::IpAddr;
use std::str::FromStr;
use tui_input::{backend::crossterm::EventHandler, Input};

#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    name: String,
    enabled: bool,
    ip: Option<IpAddr>,
    port: Option<u16>,
}
impl FirewallRule {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            enabled: false,
            ip: None,
            port: None,
        }
    }

    pub fn update(&mut self, inputs: Inputs) {
        match inputs.focus {
            FocusedInput::Name => self.name = inputs.name.value().into(),
            FocusedInput::Ip => {
                let ip = IpAddr::from_str(inputs.ip.value());
                match ip {
                    Ok(ipaddr) => self.ip = Some(ipaddr),
                    _ => {} //TODO: error notif
                }
            }
            FocusedInput::Port => {
                let p = String::from(inputs.port).parse::<u16>();
                match p {
                    Ok(port) => self.port = Some(port),
                    _ => {} //TODO: error notif
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    is_editing: bool,
    focused_rule: Option<FirewallRule>,
    inputs: Inputs,
}
#[derive(Debug, Clone)]
pub enum FocusedInput {
    Name,
    Ip,
    Port,
}

#[derive(Debug, Clone)]
struct Inputs {
    pub name: Input,
    pub ip: Input,
    pub port: Input,
    pub focus: FocusedInput,
}

impl Inputs {
    pub fn new() -> Self {
        Self {
            name: Input::new("".to_string()),
            ip: Input::new("".to_string()),
            port: Input::new("".to_string()),
            focus: FocusedInput::Name,
        }
    }
    pub fn reset(&mut self) {
        self.name.reset();
        self.ip.reset();
        self.port.reset();
    }

    pub fn handle_event(&mut self, event: &crossterm::event::Event) {
        let _ = match self.focus {
            FocusedInput::Name => self.name.handle_event(event),
            FocusedInput::Ip => self.ip.handle_event(event),
            FocusedInput::Port => self.port.handle_event(event),
        };
    }
    pub fn render(&mut self, frame: &mut Frame, block: Rect) {
        let edited_value = match self.focus {
            FocusedInput::Name => self.name.value(),
            FocusedInput::Ip => self.ip.value(),
            FocusedInput::Port => self.port.value(),
        };

        Paragraph::new(format!("> {}", edited_value))
            .alignment(Alignment::Left)
            .style(Style::default().white())
            .block(
                Block::new()
                    .borders(Borders::TOP)
                    .title(" Search  ")
                    .padding(Padding::horizontal(1))
                    .title_style({ Style::default().bold().yellow() }),
            );

        frame.render_widget(fuzzy, fuzzy_block);
    }
}

impl From<FirewallRule> for Inputs {
    fn from(rule: FirewallRule) -> Self {
        Self {
            name: Input::new(rule.name),
            ip: Input::new(match rule.ip {
                Some(ip) => ip.to_string(),
                None => "".to_string(),
            }),
            port: Input::new(match rule.port {
                Some(port) => port.to_string(),
                None => "".to_string(),
            }),
            focus: FocusedInput::Name,
        }
    }
}

impl Firewall {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            is_editing: false,
            focused_rule: None,
            inputs: Inputs::new(),
        }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        if self.rules.iter().any(|r| r.name == rule.name) {
            return;
        }
        self.rules.push(rule);
    }
    pub fn remove_rule(&mut self, rule: &FirewallRule) {
        self.rules.retain(|r| r.name != rule.name);
    }
    pub fn handle_keys(&mut self, key_event: KeyEvent) {
        if self.is_editing {
            match key_event.code {
                KeyCode::Esc => {
                    self.is_editing = false;
                    self.inputs.reset()
                }
                KeyCode::Enter => {
                    self.is_editing = false;
                    self.focused_rule
                        .as_mut()
                        .unwrap()
                        .update(self.inputs.clone());
                    self.inputs.reset();
                }
                _ => {
                    self.inputs
                        .handle_event(&crossterm::event::Event::Key(key_event));
                }
            }
        } else {
            match key_event.code {
                KeyCode::Char('j') | KeyCode::Down => {}
                KeyCode::Char('k') | KeyCode::Up => {}
                KeyCode::Char('n') => {
                    self.is_editing = true;
                    self.add_rule(FirewallRule::new());
                }
                _ => {}
            }
        }
    }
    pub fn render(&self, frame: &mut Frame, block: Rect) {
        let widths = [
            Constraint::Min(30),
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(10),
        ];

        let rows = self.rules.iter().map(|rule| {
            if self.is_editing && self.focused_rule.as_ref().unwrap().name == rule.name {
                Row::new(vec![
                    Line::from(rule.name.clone()).centered().bold(),
                    Line::from({
                        if let Some(ip) = rule.ip {
                            ip.to_string()
                        } else {
                            "-".to_string()
                        }
                    })
                    .centered()
                    .bold(),
                    Line::from({
                        if let Some(port) = rule.port {
                            port.to_string()
                        } else {
                            "-".to_string()
                        }
                    })
                    .centered(),
                    Line::from(rule.enabled.to_string()).centered(),
                ])
            } else {
                Row::new(vec![
                    Line::from(rule.name.clone()).centered().bold(),
                    Line::from({
                        if let Some(ip) = rule.ip {
                            ip.to_string()
                        } else {
                            "-".to_string()
                        }
                    })
                    .centered()
                    .bold(),
                    Line::from({
                        if let Some(port) = rule.port {
                            port.to_string()
                        } else {
                            "-".to_string()
                        }
                    })
                    .centered(),
                    Line::from(rule.enabled.to_string()).centered(),
                ])
            }
        });
        let table = Table::new(rows, widths)
            .column_spacing(2)
            .flex(Flex::SpaceBetween)
            .header(
                Row::new(vec![
                    Line::from("Name").centered(),
                    Line::from("IP Address").centered(),
                    Line::from("Port").centered(),
                    Line::from("Enabled?").centered(),
                ])
                .style(Style::new().bold())
                .bottom_margin(1),
            )
            .block(
                Block::new()
                    .title(" Firewall Rules ")
                    .borders(Borders::all())
                    .border_style(Style::new().yellow())
                    .title_alignment(Alignment::Center)
                    .padding(Padding::uniform(2)),
            );

        frame.render_widget(table, block);
    }
}

// Paragraph::new(format!("> {}", fuzzy.filter.value()))
// .alignment(Alignment::Left)
// .style(Style::default().white())
// .block(
//     Block::new()
//         .borders(Borders::TOP)
//         .title(" Search  ")
//         .padding(Padding::horizontal(1))
//         .title_style({
//             if fuzzy.is_paused() {
//                 Style::default().bold().yellow()
//             } else {
//                 Style::default().bold().green()
//             }
//         })
//         .border_type({
//             if fuzzy.is_paused() {
//                 BorderType::default()
//             } else {
//                 BorderType::Thick
//             }
//         })
//         .border_style({
//             if fuzzy.is_paused() {
//                 Style::default().yellow()
//             } else {
//                 Style::default().green()
//             }
//         }),
