use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::num::ParseIntError;

pub mod tcp;
pub mod udp;

use tcp::TcpConnectionMap;
use udp::UdpConnectionMap;

use crate::app::AppResult;
use crate::packet::network::{IpPacket, IpProto};
use crate::packet::NetworkPacket;

pub fn get_pid(packet: NetworkPacket, map: &ConnectionMap) -> Option<usize> {
    match packet {
        NetworkPacket::Ip(ip_packet) => match ip_packet {
            IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                IpProto::Tcp(tcp_packet) => {
                    let connection = Connection {
                        ip_local: IpAddr::V4(ipv4_packet.src_ip),
                        port_local: Some(tcp_packet.src_port),
                        ip_remote: IpAddr::V4(ipv4_packet.dst_ip),
                        port_remote: Some(tcp_packet.dst_port),
                    };
                    return map.tcp.map.get(&connection.calculate_hash()).copied();
                }

                IpProto::Udp(udp_packet) => {
                    let connection = Connection {
                        ip_local: IpAddr::V4(ipv4_packet.src_ip),
                        port_local: Some(udp_packet.src_port),
                        ip_remote: IpAddr::V4(ipv4_packet.dst_ip),
                        port_remote: Some(udp_packet.dst_port),
                    };
                    return map.udp.map.get(&connection.calculate_hash()).copied();
                }
                _ => {}
            },
            _ => {}
        },
        _ => {}
    };
    None
}

fn decode_hex_ipv4(hex_str: &str) -> AppResult<[u8; 4]> {
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)?;
        bytes.push(byte);
    }
    let mut res: [u8; 4] = bytes.as_slice().try_into()?;
    res.reverse();
    Ok(res)
}

fn decode_hex_port(hex_str: &str) -> Result<u16, ParseIntError> {
    Ok(u16::from_be_bytes([
        u8::from_str_radix(&hex_str[..2], 16)?,
        u8::from_str_radix(&hex_str[2..], 16)?,
    ]))
}

#[derive(Clone, Debug)]
pub struct ConnectionMap {
    pub tcp: TcpConnectionMap,
    pub udp: UdpConnectionMap,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            tcp: TcpConnectionMap::new(),
            udp: UdpConnectionMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Connection {
    ip_local: IpAddr,
    port_local: Option<u16>,
    ip_remote: IpAddr,
    port_remote: Option<u16>,
}

impl Hash for Connection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip_local.hash(state);
        self.port_local.hash(state);
        self.ip_remote.hash(state);
        self.port_remote.hash(state);
    }
}

impl Connection {
    pub fn calculate_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }
}
