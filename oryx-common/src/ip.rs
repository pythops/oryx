// use core::fmt::Display;
//
// use core::net::{Ipv4Addr, Ipv6Addr};
//
// #[derive(Debug, Copy, Clone)]
// pub enum IpPacket {
//     V4(Ipv4Packet),
//     V6(Ipv6Packet),
// }
//
// #[derive(Debug, Copy, Clone)]
// pub struct Ipv4Packet {
//     pub src_ip: Ipv4Addr,
//     pub dst_ip: Ipv4Addr,
//     pub ihl: u8,
//     pub tos: u8,
//     pub total_length: u16,
//     pub id: u16,
//     pub fragment_offset: u16,
//     pub ttl: u8,
//     pub proto: IpProto,
//     pub checksum: u16,
// }
//
// #[derive(Debug, Copy, Clone)]
// pub struct Ipv6Packet {
//     pub src_ip: Ipv6Addr,
//     pub dst_ip: Ipv6Addr,
//     pub proto: IpProto,
// }
//
// #[derive(Debug, Copy, Clone)]
// pub enum IpProto {
//     Tcp(TcpPacket),
//     Udp(UdpPacket),
//     Icmp(IcmpPacket),
// }
//
// #[derive(Debug, Copy, Clone)]
// pub struct TcpPacket {
//     pub dst_port: u16,
//     pub src_port: u16,
// }
//
// #[derive(Debug, Copy, Clone)]
// pub struct UdpPacket {
//     pub dst_port: u16,
//     pub src_port: u16,
// }
//
// #[derive(Debug, Copy, Clone)]
// pub struct IcmpPacket {
//     pub icmp_type: IcmpType,
// }
//
// #[derive(Debug, Copy, Clone)]
// pub enum IcmpType {
//     EchoRequest,
//     EchoReply,
//     DestinationUnreachable,
// }
//
// impl Display for IcmpType {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             IcmpType::EchoReply => {
//                 write!(f, "Echo Reply")
//             }
//             IcmpType::EchoRequest => {
//                 write!(f, "Echo Request")
//             }
//             IcmpType::DestinationUnreachable => {
//                 write!(f, "Destination Unreachable")
//             }
//         }
//     }
// }
//
// impl Display for IpPacket {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
//                 IpProto::Tcp(tcp_packet) => {
//                     write!(
//                         f,
//                         "{} {} {} {} TCP",
//                         ipv4_packet.src_ip,
//                         tcp_packet.src_port,
//                         ipv4_packet.dst_ip,
//                         tcp_packet.dst_port
//                     )
//                 }
//                 IpProto::Udp(udp_packet) => {
//                     write!(
//                         f,
//                         "{} {} {} {} UDP",
//                         ipv4_packet.src_ip,
//                         udp_packet.src_port,
//                         ipv4_packet.dst_ip,
//                         udp_packet.dst_port
//                     )
//                 }
//                 IpProto::Icmp(_) => {
//                     write!(f, "{} {} ICMP", ipv4_packet.src_ip, ipv4_packet.dst_ip)
//                 }
//             },
//             IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
//                 IpProto::Tcp(tcp_packet) => {
//                     write!(
//                         f,
//                         "{} {} {} {} TCP",
//                         ipv6_packet.src_ip,
//                         tcp_packet.src_port,
//                         ipv6_packet.dst_ip,
//                         tcp_packet.dst_port
//                     )
//                 }
//                 IpProto::Udp(udp_packet) => {
//                     write!(
//                         f,
//                         "{} {} {} {} UDP",
//                         ipv6_packet.src_ip,
//                         udp_packet.src_port,
//                         ipv6_packet.dst_ip,
//                         udp_packet.dst_port
//                     )
//                 }
//                 IpProto::Icmp(_) => {
//                     write!(f, "{} {} ICMP", ipv6_packet.src_ip, ipv6_packet.dst_ip)
//                 }
//             },
//         }
//     }
// }
