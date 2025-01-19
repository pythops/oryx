use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Style, Stylize},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Padding, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    Frame,
};

#[derive(Debug, Clone, Default)]
pub struct Help {
    block_height: usize,
    state: TableState,
    keys: Vec<(Cell<'static>, &'static str)>,
}

impl Help {
    pub fn new() -> Self {
        let mut state = TableState::new().with_offset(0);
        state.select(Some(0));

        Self {
            block_height: 0,
            state,
            keys: vec![
                (
                    Cell::from("Esc").bold(),
                    "Dismiss different pop-ups and modes",
                ),
                (
                    Cell::from("Tab or Shift+Tab").bold(),
                    "Switch between different sections",
                ),
                (Cell::from("j or Down").bold(), "Scroll down"),
                (Cell::from("k or Up").bold(), "Scroll up"),
                (Cell::from("?").bold(), "Show help"),
                (Cell::from("q or ctrl+c").bold(), "Quit"),
                (
                    Cell::from("Space").bold(),
                    "Select/Deselect interface or filter",
                ),
                (Cell::from("f").bold(), "Update the applied filters"),
                (Cell::from("ctrl + r").bold(), "Reset the app"),
                (
                    Cell::from("ctrl + s").bold(),
                    "Export the capture to ~/oryx/capture file",
                ),
                (Cell::from(""), ""),
                (Cell::from("## Inspection").bold().yellow(), ""),
                (
                    Cell::from("i").bold(),
                    "Show more infos about the selected packet",
                ),
                (Cell::from("/").bold(), "Start fuzzy finding"),
                (Cell::from(""), ""),
                (Cell::from("## Firewall").bold().yellow(), ""),
                (Cell::from("n").bold(), "Add new firewall rule"),
                (Cell::from("e").bold(), "Edit a firewall rule"),
                (
                    Cell::from("s").bold(),
                    "Save firewall rules to ~/oryx/firewall.json ",
                ),
                (Cell::from("Space").bold(), "Toggle firewall rule status"),
                (Cell::from("Enter").bold(), "Create or Save a firewall rule"),
            ],
        }
    }

    pub fn scroll_down(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.keys.len().saturating_sub(self.block_height - 6) {
                    i
                } else {
                    i + 1
                }
            }
            None => 1,
        };
        *self.state.offset_mut() = i;
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
            None => 1,
        };
        *self.state.offset_mut() = i;
        self.state.select(Some(i));
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(26),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(frame.area());

        let block = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(70),
                Constraint::Fill(1),
            ])
            .flex(ratatui::layout::Flex::SpaceBetween)
            .split(layout[1])[1];

        self.block_height = block.height as usize;
        let widths = [Constraint::Length(20), Constraint::Fill(1)];
        let rows = self.keys.iter().map(|key| {
            Row::new(vec![key.0.to_owned(), key.1.into()]).style(Style::default().fg(Color::White))
        });
        let rows_len = self.keys.len().saturating_sub(self.block_height - 6);

        let table = Table::new(rows, widths).block(
            Block::default()
                .padding(Padding::uniform(2))
                .title(" Help ")
                .title_style(Style::default().bold().fg(Color::Green))
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .style(Style::default())
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(Color::Green)),
        );

        frame.render_widget(Clear, block);
        frame.render_stateful_widget(table, block, &mut self.state);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut scrollbar_state =
            ScrollbarState::new(rows_len).position(self.state.selected().unwrap_or_default());
        frame.render_stateful_widget(
            scrollbar,
            block.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}
