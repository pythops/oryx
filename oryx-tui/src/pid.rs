use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek};

use std::net::IpAddr;
use std::num::ParseIntError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use itertools::chain;
use log::info;

use crate::app::AppResult;

#[derive(Clone, Debug)]
pub struct Connection {
    ip_local: IpAddr,
    port_local: u16,
    ip_remote: IpAddr,
    port_remote: u16,
    inode: u32,
    pub pid: Option<u32>,
}
impl Connection {
    pub fn key(&self) -> String {
        format!(
            "{}:{}_{}:{}",
            self.ip_local, self.port_local, self.ip_remote, self.port_remote
        )
    }
    fn try_get_pid(&mut self, inode_pid_map_map: &HashMap<u32, u32>) {
        self.pid = inode_pid_map_map.get(&self.inode).copied();
    }
}

impl TryFrom<&Vec<&str>> for Connection {
    type Error = Box<dyn std::error::Error>;
    fn try_from(splits: &Vec<&str>) -> Result<Self, Self::Error> {
        let ip_local: &str = splits[1];
        let mut ip_local_port = ip_local.split(":");
        let ip_local = ip_local_port.next().unwrap();
        let port_local = ip_local_port.next().unwrap();

        let ip_local = match decode_hex_ipv4(ip_local) {
            Ok(ip) => IpAddr::try_from(ip)?,
            _ => IpAddr::try_from(decode_hex_ipv6(ip_local)?)?,
        };

        let port_local = decode_hex_port(port_local)?;

        let ip_remote = splits[2];
        let mut ip_remote_port = ip_remote.split(":");
        let ip_remote = ip_remote_port.next().unwrap();
        let port_remote = ip_remote_port.next().unwrap();

        let ip_remote = match decode_hex_ipv4(ip_remote) {
            Ok(ip) => IpAddr::try_from(ip)?,
            _ => IpAddr::try_from(decode_hex_ipv6(ip_remote)?)?,
        };
        let port_remote = decode_hex_port(port_remote)?;

        let inode = splits[9].parse::<u32>().unwrap();

        Ok(Self {
            ip_local,
            port_local,
            ip_remote,
            port_remote,

            inode,
            pid: None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct IpMap {
    pub map: HashMap<String, Connection>,
}

impl IpMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

fn build_inode_map(target_inodes: Vec<u32>) -> HashMap<u32, u32> {
    let mut res = HashMap::<u32, u32>::new();
    // Iterate over all directories in /proc (these represent PIDs)
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_str().unwrap().to_string();
            if !pid_str.chars().all(char::is_numeric) {
                continue;
            }
            let fd_dir = format!("/proc/{}/fd", pid_str);
            if let Ok(fds) = fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    let link_path = fd.path();

                    if let Ok(link_target) = fs::read_link(&link_path) {
                        // Socket inodes are typically shown as "socket:[inode]"
                        if let Some(inode_str) = link_target.to_str() {
                            if inode_str.starts_with("socket:[") && inode_str.ends_with(']') {
                                if let Ok(inode) = inode_str[8..inode_str.len() - 1].parse::<u32>()
                                {
                                    if target_inodes.contains(&inode) {
                                        res.insert(inode, pid_str.parse::<u32>().unwrap());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    res
}
fn decode_hex_port(hex_str: &str) -> Result<u16, ParseIntError> {
    Ok(u16::from_be_bytes([
        u8::from_str_radix(&hex_str[..2], 16)?,
        u8::from_str_radix(&hex_str[2..], 16)?,
    ]))
}

fn decode_hex_ipv4(hex_str: &str) -> AppResult<[u8; 4]> {
    let mut bytes = Vec::new();
    // Iterate over the string in chunks of 2 characters
    for i in (0..hex_str.len()).step_by(2) {
        // Get the current 2-character chunk
        let byte_str = &hex_str[i..i + 2];

        let byte = u8::from_str_radix(byte_str, 16)?;
        bytes.push(byte);
    }
    let mut res: [u8; 4] = bytes.as_slice().try_into()?;
    res.reverse();
    Ok(res)
}

fn decode_hex_ipv6(hex_str: &str) -> AppResult<[u8; 4]> {
    let mut bytes = Vec::new();
    // Iterate over the string in chunks of 2 characters
    for i in (0..hex_str.len()).step_by(4) {
        // Get the current 2-character chunk
        let byte_str = &hex_str[i..i + 4];

        let byte = u8::from_str_radix(byte_str, 16)?;
        bytes.push(byte);
    }
    let mut res: [u8; 4] = bytes.as_slice().try_into()?;
    res.reverse();
    Ok(res)
}

#[derive(Debug)]
pub struct ConnectionsInfo {
    sender: kanal::Sender<(IpMap, IpMap)>,
}

impl ConnectionsInfo {
    pub fn get_used_inodes(tcp_map: &IpMap, udp_map: &IpMap) -> Vec<u32> {
        let mut res = Vec::new();

        for (_, conn) in tcp_map.map.iter() {
            res.push(conn.inode);
        }

        for (_, conn) in udp_map.map.iter() {
            res.push(conn.inode);
        }
        res
    }
    pub fn new(sender: kanal::Sender<(IpMap, IpMap)>) -> Self {
        Self { sender }
    }

    pub fn spawn(&self) {
        let tcp_map: Arc<Mutex<IpMap>> = Arc::new(Mutex::new(IpMap::new()));
        let udp_map: Arc<Mutex<IpMap>> = Arc::new(Mutex::new(IpMap::new()));
        thread::spawn({
            let tcp_map = tcp_map.clone();
            let mut fd_tcp = File::open("/proc/net/tcp").unwrap();
            let mut fd_tcp6 = File::open("/proc/net/tcp6").unwrap();
            move || {
                loop {
                    thread::sleep(Duration::from_millis(250));
                    fd_tcp.seek(std::io::SeekFrom::Start(0)).unwrap();
                    fd_tcp6.seek(std::io::SeekFrom::Start(0)).unwrap();

                    let mut buffer_tcp = String::new();
                    let mut buffer_tcp6 = String::new();
                    fd_tcp.read_to_string(&mut buffer_tcp).unwrap();
                    fd_tcp6.read_to_string(&mut buffer_tcp6).unwrap();

                    let mut lines_tcp = buffer_tcp.lines();
                    let mut lines_tcp6 = buffer_tcp6.lines();
                    lines_tcp.next(); //header
                    lines_tcp6.next(); //header

                    let mut map = tcp_map.lock().unwrap();
                    for line in chain(lines_tcp, lines_tcp6) {
                        let splits: Vec<&str> = line.split_whitespace().collect();

                        match Connection::try_from(&splits) {
                            Ok(conn) => {
                                map.map.insert(conn.key(), conn);
                            }
                            _ => {} //error!("error parsing tcp conn{:#?}", splits)},
                        }
                    }
                    info!("{:#?}", map);
                }
            }
        });

        thread::spawn({
            let udp_map = udp_map.clone();

            move || {
                let mut fd_udp = File::open("/proc/net/udp").unwrap();

                loop {
                    thread::sleep(Duration::from_millis(250));
                    fd_udp.seek(std::io::SeekFrom::Start(0)).unwrap();
                    let mut buffer = String::new();
                    fd_udp.read_to_string(&mut buffer).unwrap();

                    let mut lines = buffer.lines();

                    lines.next(); //header
                    let mut map = udp_map.lock().unwrap();
                    for line in lines {
                        let splits: Vec<&str> = line.split_whitespace().collect();

                        match Connection::try_from(&splits) {
                            Ok(conn) => {
                                map.map.insert(conn.key(), conn);
                            }
                            _ => {} //error!("error parsing  udp conn {:#?}", splits),
                        }
                    }
                }
            }
        });

        thread::spawn({
            let tcp_map = tcp_map.clone();
            let udp_map = udp_map.clone();
            let sender = self.sender.clone();
            move || loop {
                thread::sleep(Duration::from_millis(500));

                let mut _udp_map = udp_map.lock().unwrap();
                let mut _tcp_map = tcp_map.lock().unwrap();

                let inodes = Self::get_used_inodes(&_tcp_map, &_udp_map);

                let inode_pid_map_map = build_inode_map(inodes);

                for (_, conn) in _udp_map.map.iter_mut() {
                    conn.try_get_pid(&inode_pid_map_map);
                }
                for (_, conn) in _tcp_map.map.iter_mut() {
                    conn.try_get_pid(&inode_pid_map_map);
                }

                sender.send((_tcp_map.clone(), _udp_map.clone())).ok();
            }
        });
    }
}
