use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::symbols;
use ratatui::widgets::{Axis, Chart, Dataset, GraphType};
use ratatui::{
    widgets::{Block, Padding},
    Frame,
};

#[derive(Clone, Debug)]
pub struct BandwidthBuffer {
    incoming_max: usize,
    outgoing_max: usize,
    data: VecDeque<(usize, usize)>,
}

impl BandwidthBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            incoming_max: 0,
            outgoing_max: 0,
            data: VecDeque::with_capacity(capacity),
        }
    }

    fn push(&mut self, item: (usize, usize)) {
        if self.data.len() == self.data.capacity() {
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
    map: Arc<Mutex<HashMap<String, BandwidthBuffer>>>,
}

impl Default for Bandwidth {
    fn default() -> Self {
        Self::new()
    }
}

impl Bandwidth {
    pub fn new() -> Self {
        let map: Arc<Mutex<HashMap<String, BandwidthBuffer>>> =
            Arc::new(Mutex::new(HashMap::new()));

        thread::spawn({
            let map = map.clone();
            move || {
                //TODO: handle error
                let mut fd = File::open("/proc/net/dev").unwrap();
                let mut current: HashMap<String, (usize, usize)> = HashMap::new();

                let mut buffer = String::new();
                fd.read_to_string(&mut buffer).unwrap();
                let mut lines = buffer.lines();

                lines.next();
                lines.next();

                for line in lines {
                    let splits: Vec<&str> = line.split_whitespace().collect();

                    let mut interface_name = splits[0].to_string();
                    interface_name.pop();

                    let bandwidth_buffer = BandwidthBuffer::new(20);

                    let received: usize = splits[1].parse().unwrap();
                    let sent: usize = splits[9].parse().unwrap();

                    current.insert(interface_name.clone(), (received, sent));

                    {
                        let mut map = map.lock().unwrap();
                        map.insert(interface_name, bandwidth_buffer);
                    }
                }

                loop {
                    thread::sleep(Duration::from_secs(1));
                    fd.seek(std::io::SeekFrom::Start(0)).unwrap();
                    let mut buffer = String::new();
                    fd.read_to_string(&mut buffer).unwrap();

                    let mut lines = buffer.lines();

                    lines.next();
                    lines.next();

                    for line in lines {
                        let splits: Vec<&str> = line.split_whitespace().collect();

                        let mut interface_name = splits[0].to_string();
                        interface_name.pop();

                        let received: usize = splits[1].parse().unwrap();
                        let sent: usize = splits[9].parse().unwrap();

                        let mut map = map.lock().unwrap();
                        if let Some(bandwidth_buffer) = map.get_mut(&interface_name) {
                            let current = current.get_mut(&interface_name).unwrap();
                            bandwidth_buffer.push((
                                received.saturating_sub(current.0) / 1024,
                                sent.saturating_sub(current.1) / 1024,
                            ));
                            current.0 = received;
                            current.1 = sent;
                        }
                    }
                }
            }
        });

        Self { map }
    }

    pub fn render(&self, frame: &mut Frame, bandwidth_block: Rect, network_interface: &str) {
        let map = self.map.lock().unwrap();
        let (incoming_block, outgoing_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .margin(1)
                .split(bandwidth_block);
            (chunks[0], chunks[1])
        };
        let (incoming_max_val, incoming_unit) =
            if let Some(bandwidth_buffer) = map.get(network_interface) {
                match bandwidth_buffer.incoming_max {
                    n if (1024usize.pow(2)..1024usize.pow(3)).contains(&n) => {
                        ((n / 1024usize.pow(2)) as f64, "GB")
                    }
                    n if (1024..1024usize.pow(2)).contains(&n) => ((n / 1000) as f64, "MB"),
                    n => (n as f64, "KB"),
                }
            } else {
                (0f64, "KB")
            };

        let (outgoing_max_val, outgoing_unit) =
            if let Some(bandwidth_buffer) = map.get(network_interface) {
                match bandwidth_buffer.outgoing_max {
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
            if let Some(v) = map.get(network_interface) {
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
            if let Some(v) = map.get(network_interface) {
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
