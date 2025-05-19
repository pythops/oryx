use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::Span,
    widgets::{Block, Borders, Padding, Paragraph, Row, Table},
    Frame,
};

#[derive(Debug, Copy, Clone)]
pub struct TcpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub data_offset: u16,
    pub cwr: u16,
    pub ece: u16,
    pub urg: u16,
    pub ack: u16,
    pub psh: u16,
    pub rst: u16,
    pub syn: u16,
    pub fin: u16,
    pub window: u16,
    pub checksum: u16,
    pub urg_ptr: u16,
}

impl TcpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };

        let title = Paragraph::new("TCP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(self.src_port.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(self.dst_port.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Sequence Number", Style::new().bold()),
                Span::from(self.seq.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Acknowledgment Number", Style::new().bold()),
                Span::from(self.ack_seq.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Data Offset", Style::new().bold()),
                Span::from(self.data_offset.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Congestion Window Reduced", Style::new().bold()),
                Span::from(self.cwr.to_string()),
            ]),
            Row::new(vec![
                Span::styled("ECE", Style::new().bold()),
                Span::from(self.ece.to_string()),
            ]),
            Row::new(vec![
                Span::styled("URG", Style::new().bold()),
                Span::from(self.urg.to_string()),
            ]),
            Row::new(vec![
                Span::styled("ACK", Style::new().bold()),
                Span::from(self.ack.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Push", Style::new().bold()),
                Span::from(self.psh.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Reset", Style::new().bold()),
                Span::from(self.rst.to_string()),
            ]),
            Row::new(vec![
                Span::styled("SYN", Style::new().bold()),
                Span::from(self.syn.to_string()),
            ]),
            Row::new(vec![
                Span::styled("FIN", Style::new().bold()),
                Span::from(self.fin.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Window", Style::new().bold()),
                Span::from(self.window.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
            Row::new(vec![
                Span::styled("Urgent Pointer", Style::new().bold()),
                Span::from(self.urg_ptr.to_string()),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().yellow())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UdpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        let (title_block, data_block) = {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(10), Constraint::Fill(1)])
                .margin(2)
                .split(block);

            (chunks[0], chunks[1])
        };
        let title = Paragraph::new("UDP")
            .bold()
            .block(Block::new().padding(Padding::top({
                if title_block.height % 2 == 0 {
                    (title_block.height / 2).saturating_sub(1)
                } else {
                    title_block.height / 2
                }
            })));

        let widths = [Constraint::Length(23), Constraint::Fill(1)];
        let infos = [
            Row::new(vec![
                Span::styled("Source Port", Style::new().bold()),
                Span::from(self.src_port.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Destination Port", Style::new().bold()),
                Span::from(self.dst_port.to_string()),
            ]),
            Row::new(vec![
                Span::styled("Length", Style::new().bold()),
                Span::from(format!("{} bytes", self.length)),
            ]),
            Row::new(vec![
                Span::styled("Checksum", Style::new().bold()),
                Span::from(format!("{:#0x}", self.checksum)),
            ]),
        ];

        let table = Table::new(infos, widths).column_spacing(2).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::new().bold().yellow())
                .border_type(ratatui::widgets::BorderType::Thick)
                .style(Style::default()),
        );
        frame.render_widget(table, data_block);
        frame.render_widget(title, title_block);
    }
}
