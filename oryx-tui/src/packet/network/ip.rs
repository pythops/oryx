pub mod ipv4;
pub mod ipv6;

use crate::packet::{
    network::icmp::IcmpPacket,
    transport::{SctpPacket, TcpPacket, UdpPacket},
};

#[derive(Debug, Copy, Clone)]
pub enum IpProto {
    Tcp(TcpPacket),
    Udp(UdpPacket),
    Sctp(SctpPacket),
    Icmp(IcmpPacket),
}
