use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek};

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::symbols;
use ratatui::widgets::{Axis, Chart, Dataset, GraphType};
use ratatui::{
    widgets::{Block, Padding},
    Frame,
};

use crate::app::AppResult;

#[derive(Clone, Debug)]
pub struct BandwidthBuffer {
    incoming_max: usize,
    outgoing_max: usize,
    data: VecDeque<(usize, usize)>,
    capacity: usize,
}

impl BandwidthBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            incoming_max: 0,
            outgoing_max: 0,
            data: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, item: (usize, usize)) {
        if self.data.len() == self.capacity {
            self.data.pop_back();
        }
        self.data.push_front(item);

        self.incoming_max = self.data.iter().map(|&(x, _)| x).max().unwrap();
        self.outgoing_max = self.data.iter().map(|&(_, y)| y).max().unwrap();
    }

    fn get(&self) -> VecDeque<(usize, usize)> {
        self.data.clone()
    }
}

#[derive(Debug)]
pub struct Bandwidth {
    fd: File,
    current: HashMap<String, (usize, usize)>,
    pub map: HashMap<String, BandwidthBuffer>,
}

impl Bandwidth {
    pub fn new() -> AppResult<Self> {
        let mut fd = File::open("/proc/net/dev")?;
        let mut current: HashMap<String, (usize, usize)> = HashMap::new();
        let mut map: HashMap<String, BandwidthBuffer> = HashMap::new();

        let mut buffer = String::new();
        fd.read_to_string(&mut buffer)?;
        let mut lines = buffer.lines();

        lines.next();
        lines.next();

        for line in lines {
            let splits: Vec<&str> = line.split_whitespace().collect();

            let mut name = splits[0].to_string();
            name.pop();

            let ring_buffer = BandwidthBuffer::new(20);

            let received: usize = splits[1].parse()?;
            let sent: usize = splits[9].parse()?;

            current.insert(name.clone(), (received, sent));

            map.insert(name, ring_buffer);
        }

        Ok(Self { fd, current, map })
    }

    pub fn refresh(&mut self) -> AppResult<()> {
        self.fd.seek(std::io::SeekFrom::Start(0))?;
        let mut buffer = String::new();
        self.fd.read_to_string(&mut buffer)?;

        let mut lines = buffer.lines();

        lines.next();
        lines.next();

        for line in lines {
            let splits: Vec<&str> = line.split_whitespace().collect();

            let mut name = splits[0].to_string();
            name.pop();

            let received: usize = splits[1].parse()?;
            let sent: usize = splits[9].parse()?;

            if let Some(v) = self.map.get_mut(&name) {
                let current = self.current.get_mut(&name).unwrap();
                v.push((
                    received.saturating_sub(current.0) / 1024,
                    sent.saturating_sub(current.1) / 1024,
                ));
                current.0 = received;
                current.1 = sent;
            }
        }
        Ok(())
    }

    pub fn render(&self, frame: &mut Frame, bandwidth_block: Rect, network_interface: &str) {
        let (incoming_block, outgoing_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(1)
                .split(bandwidth_block);
            (chunks[0], chunks[1])
        };
        let (incoming_max_val, incoming_unit) = if let Some(v) = self.map.get(network_interface) {
            match v.incoming_max {
                n if (1024usize.pow(2)..1024usize.pow(3)).contains(&n) => {
                    ((n / 1024usize.pow(2)) as f64, "GB")
                }
                n if (1024..1024usize.pow(2)).contains(&n) => ((n / 1024) as f64, "MB"),
                n => (n as f64, "KB"),
            }
        } else {
            (0f64, "KB")
        };

        let (outgoing_max_val, outgoing_unit) = if let Some(v) = self.map.get(network_interface) {
            match v.outgoing_max {
                n if (1024usize.pow(2)..1024usize.pow(3)).contains(&n) => {
                    ((n / 1024usize.pow(2)) as f64, "GB")
                }
                n if (1024..1024usize.pow(2)).contains(&n) => ((n / 1024) as f64, "MB"),
                n => (n as f64, "KB"),
            }
        } else {
            (0f64, "KB")
        };

        let incoming_data = {
            if let Some(v) = self.map.get(network_interface) {
                let values = v.get();
                let x: Vec<(f64, f64)> = values
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(index, (x, _))| match x {
                        n if (1024usize.pow(2)..1024usize.pow(3)).contains(n) => {
                            (index as f64, (n / 1024usize.pow(2)) as f64)
                        }
                        n if (1024..1024usize.pow(2)).contains(n) => {
                            (index as f64, (n / 1024) as f64)
                        }
                        n => (index as f64, n.to_owned() as f64),
                    })
                    .collect::<Vec<(f64, f64)>>();
                x
            } else {
                vec![(0f64, 0f64)]
            }
        };

        let outgoing_data = {
            if let Some(v) = self.map.get(network_interface) {
                let values = v.get();
                let x: Vec<(f64, f64)> = values
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(index, (_, y))| match y {
                        n if (1024usize.pow(2)..1024usize.pow(3)).contains(n) => {
                            (index as f64, (n / 1024usize.pow(2)) as f64)
                        }
                        n if (1024..1024usize.pow(2)).contains(n) => {
                            (index as f64, (n / 1024) as f64)
                        }
                        n => (index as f64, n.to_owned() as f64),
                    })
                    .collect::<Vec<(f64, f64)>>();
                x
            } else {
                vec![(0f64, 0f64)]
            }
        };

        let incomig_dataset = vec![Dataset::default()
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().cyan())
            .data(&incoming_data)];

        let outgoing_dataset = vec![Dataset::default()
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().magenta())
            .data(&outgoing_data)];

        let x_axis = Axis::default()
            .style(Style::default().white())
            .bounds([0.0, 20.0])
            .labels(["0", "5", "10", "15", "20"]);

        // Incoming
        // Create the Y axis and define its properties
        let incomig_y_axis = Axis::default()
            .style(Style::default().white())
            .bounds([0.0, incoming_max_val * 1.25])
            .labels([0.to_string(), format!("{incoming_max_val} {incoming_unit}")]);

        // Create the chart and link all the parts together
        let incoming_chart = Chart::new(incomig_dataset)
            .block(
                Block::new()
                    .padding(Padding::uniform(2))
                    .title(" Incoming 󰁆 ")
                    .title_style(Style::default().cyan())
                    .title_alignment(Alignment::Center),
            )
            .x_axis(x_axis.clone())
            .y_axis(incomig_y_axis);

        // Outgoing
        // Create the Y axis and define its properties
        let outgoing_y_axis = Axis::default()
            .style(Style::default().white())
            .bounds([0.0, outgoing_max_val * 1.25])
            .labels([0.to_string(), format!("{outgoing_max_val} {outgoing_unit}")]);

        // Create the chart and link all the parts together
        let outgoing_chart = Chart::new(outgoing_dataset)
            .block(
                Block::new()
                    .padding(Padding::uniform(2))
                    .title(" Outgoing 󰁞 ")
                    .title_style(Style::default().magenta())
                    .title_alignment(Alignment::Center),
            )
            .x_axis(x_axis)
            .y_axis(outgoing_y_axis);

        frame.render_widget(incoming_chart, incoming_block);

        frame.render_widget(outgoing_chart, outgoing_block);
    }
}
