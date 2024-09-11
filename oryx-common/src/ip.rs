use core::{fmt::Display, net::IpAddr};

use network_types::{icmp::IcmpHdr, tcp::TcpHdr, udp::UdpHdr};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TcpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpPacket {
    pub dst_port: u16,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum IpPacket {
    Tcp(TcpPacket),
    Udp(UdpPacket),
    Icmp(IcmpPacket),
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Icmp(IcmpHdr),
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
