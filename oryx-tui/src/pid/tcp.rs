use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr},
};

use super::{decode_hex_ipv4, decode_hex_port, Connection};

#[derive(Clone, Debug)]
pub struct TcpConnectionMap {
    pub map: HashMap<u64, usize>,
}

impl TcpConnectionMap {
    fn inode_map() -> HashMap<usize, u64> {
        let mut map = HashMap::new();
        let mut file = File::open("/proc/net/tcp").unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();

        let mut lines_tcp = buffer.lines();
        lines_tcp.next();

        for line in lines_tcp {
            let splits: Vec<&str> = line.split_whitespace().collect();
            let ip_local: &str = splits[1];
            let mut ip_local_port = ip_local.split(":");
            let ip_local = ip_local_port.next().unwrap();
            let port_local = ip_local_port.next().unwrap();

            let ip_local = decode_hex_ipv4(ip_local).unwrap();
            let ip_local = IpAddr::V4(Ipv4Addr::from(ip_local));

            let port_local = decode_hex_port(port_local).unwrap();

            let ip_remote = splits[2];
            let mut ip_remote_port = ip_remote.split(":");
            let ip_remote = ip_remote_port.next().unwrap();
            let port_remote = ip_remote_port.next().unwrap();

            let ip_remote = decode_hex_ipv4(ip_remote).unwrap();
            let ip_remote = IpAddr::V4(Ipv4Addr::from(ip_remote));

            let port_remote = decode_hex_port(port_remote).unwrap();

            let inode = splits[9].parse::<usize>().unwrap();

            let connection = Connection {
                ip_local,
                port_local: Some(port_local),
                ip_remote,
                port_remote: Some(port_remote),
            };

            map.insert(inode, connection.calculate_hash());
        }
        map
    }

    pub fn new() -> Self {
        let mut map: HashMap<u64, usize> = HashMap::new();

        let inode_map = Self::inode_map();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name();
                let pid_str = pid_str.to_str().unwrap();
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
                                    if let Ok(inode) =
                                        inode_str[8..inode_str.len() - 1].parse::<usize>()
                                    {
                                        if let Some(connection_hash) = inode_map.get(&inode) {
                                            let pid = pid_str.parse::<usize>().unwrap();
                                            map.insert(*connection_hash, pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Self { map }
    }
}
