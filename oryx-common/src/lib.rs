#![no_std]

use core::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

impl From<[u8; 40]> for IpPacket {
    fn from(value: [u8; 40]) -> Self {
        match value[0] {
            // TCP
            0 => {
                let (src_ip, dst_ip) = if value[6] == 0 {
                    let dst_ip: [u8; 4] = value[7..11].try_into().unwrap();
                    let dst_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));

                    let src_ip: [u8; 4] = value[24..28].try_into().unwrap();
                    let src_ip = IpAddr::V4(Ipv4Addr::from(src_ip));

                    (src_ip, dst_ip)
                } else {
                    let dst_ip: [u8; 16] = value[7..23].try_into().unwrap();
                    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_ip));

                    let src_ip: [u8; 16] = value[24..40].try_into().unwrap();
                    let src_ip = IpAddr::V6(Ipv6Addr::from(src_ip));
                    (src_ip, dst_ip)
                };

                let src_port = u16::from_be_bytes([value[5], value[4]]);
                let dst_port = u16::from_be_bytes([value[3], value[2]]);

                IpPacket::Tcp(TcpPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                })
            }

            // UDP
            1 => {
                let (src_ip, dst_ip) = if value[6] == 0 {
                    let dst_ip: [u8; 4] = value[7..11].try_into().unwrap();
                    let dst_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));

                    let src_ip: [u8; 4] = value[24..28].try_into().unwrap();
                    let src_ip = IpAddr::V4(Ipv4Addr::from(src_ip));

                    (src_ip, dst_ip)
                } else {
                    let dst_ip: [u8; 16] = value[7..23].try_into().unwrap();
                    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_ip));

                    let src_ip: [u8; 16] = value[24..40].try_into().unwrap();
                    let src_ip = IpAddr::V6(Ipv6Addr::from(src_ip));
                    (src_ip, dst_ip)
                };
                let src_port = u16::from_be_bytes([value[5], value[4]]);
                let dst_port = u16::from_be_bytes([value[3], value[2]]);

                IpPacket::Udp(UdpPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                })
            }

            // ICMP
            2 => {
                let (src_ip, dst_ip) = if value[2] == 0 {
                    let dst_ip: [u8; 4] = value[3..7].try_into().unwrap();
                    let dst_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));

                    let src_ip: [u8; 4] = value[20..24].try_into().unwrap();
                    let src_ip = IpAddr::V4(Ipv4Addr::from(src_ip));

                    (src_ip, dst_ip)
                } else {
                    let dst_ip: [u8; 16] = value[3..19].try_into().unwrap();
                    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_ip));

                    let src_ip: [u8; 16] = value[20..36].try_into().unwrap();
                    let src_ip = IpAddr::V6(Ipv6Addr::from(src_ip));
                    (src_ip, dst_ip)
                };
                let icmp_type = match value[1] {
                    0 => IcmpType::EchoRequest,
                    1 => IcmpType::EchoReply,
                    _ => IcmpType::DestinationUnreachable,
                };

                IpPacket::Icmp(IcmpPacket {
                    src_ip,
                    dst_ip,
                    icmp_type,
                })
            }
            _ => {
                panic!("Error: unknown IP packet type")
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct TcpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct UdpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
}

impl Display for IcmpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IcmpType::EchoReply => {
                write!(f, "Echo Reply")
            }
            IcmpType::EchoRequest => {
                write!(f, "Echo Request")
            }
            IcmpType::DestinationUnreachable => {
                write!(f, "Destination Unreachable")
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum IpPacket {
    Tcp(TcpPacket),
    Udp(UdpPacket),
    Icmp(IcmpPacket),
}

impl Display for IpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpPacket::Tcp(p) => {
                write!(
                    f,
                    "{} {} {} {} TCP",
                    p.src_ip, p.src_port, p.dst_ip, p.dst_port
                )
            }
            IpPacket::Udp(p) => {
                write!(
                    f,
                    "{} {} {} {} UDP",
                    p.src_ip, p.src_port, p.dst_ip, p.dst_port
                )
            }
            IpPacket::Icmp(p) => {
                write!(f, "{} {} ICMP", p.src_ip, p.dst_ip)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Packet {
    Ip(IpPacket),
}
