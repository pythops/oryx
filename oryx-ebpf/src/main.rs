#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, HashMap, RingBuf},
    programs::TcContext,
};
use core::mem;
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use oryx_common::{
    protocols::{LinkProtocol, NetworkProtocol, Protocol, TransportProtocol},
    ProtoHdr, RawPacket, MAX_FIREWALL_RULES, MAX_RULES_PORT,
};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * RawPacket::LEN as u32, 0);

#[map]
static NETWORK_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static TRANSPORT_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static LINK_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static BLOCKLIST_IPV6: HashMap<u128, [u16; MAX_RULES_PORT]> =
    HashMap::<u128, [u16; MAX_RULES_PORT]>::with_max_entries(MAX_FIREWALL_RULES, 0);

#[map]
static BLOCKLIST_IPV4: HashMap<u32, [u16; MAX_RULES_PORT]> =
    HashMap::<u32, [u16; MAX_RULES_PORT]>::with_max_entries(MAX_FIREWALL_RULES, 0);

#[classifier]
pub fn oryx(ctx: TcContext) -> i32 {
    match process(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn submit(packet: RawPacket) {
    if let Some(mut buf) = DATA.reserve::<RawPacket>(0) {
        unsafe { (*buf.as_mut_ptr()) = packet };
        buf.submit(0);
    }
}
#[inline]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline]
fn filter_for_ipv4_address(
    addr: u32,
    port: u16,
    blocked_ports_map: &HashMap<u32, [u16; 32]>,
) -> bool {
    if let Some(blocked_ports) = unsafe { blocked_ports_map.get(&addr) } {
        for (idx, blocked_port) in blocked_ports.iter().enumerate() {
            if *blocked_port == 0 {
                if idx == 0 {
                    return true;
                } else {
                    break;
                }
            } else if *blocked_port == port {
                return true;
            }
        }
    }
    false
}

#[inline]
fn filter_for_ipv6_address(
    addr: u128,
    port: u16,
    blocked_ports_map: &HashMap<u128, [u16; 32]>,
) -> bool {
    if let Some(blocked_ports) = unsafe { blocked_ports_map.get(&addr) } {
        for (idx, blocked_port) in blocked_ports.iter().enumerate() {
            if *blocked_port == 0 {
                if idx == 0 {
                    return true;
                } else {
                    break;
                }
            } else if *blocked_port == port {
                return true;
            }
        }
    }
    false
}

#[inline]
fn filter_packet(protocol: Protocol) -> bool {
    match protocol {
        Protocol::Network(p) => {
            if let Some(v) = NETWORK_FILTERS.get(p as u32) {
                return *v == 1;
            }
        }
        Protocol::Transport(p) => {
            if let Some(v) = TRANSPORT_FILTERS.get(p as u32) {
                return *v == 1;
            }
        }
        Protocol::Link(p) => {
            if let Some(v) = LINK_FILTERS.get(p as u32) {
                return *v == 1;
            }
        }
    }
    false
}

#[inline]
fn process(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let header: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let src_addr = u32::from_be(header.src_addr);
            let dst_addr = u32::from_be(header.dst_addr);

            match header.proto {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = u16::from_be(unsafe { (*tcphdr).source });
                    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

                    if filter_for_ipv4_address(src_addr, src_port, &BLOCKLIST_IPV4)
                        || filter_for_ipv4_address(dst_addr, dst_port, &BLOCKLIST_IPV4)
                    {
                        return Ok(TC_ACT_SHOT);
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv4))
                        || filter_packet(Protocol::Transport(TransportProtocol::TCP))
                    {
                        return Ok(TC_ACT_PIPE); //DONT FWD PACKET TO TUI
                    }
                    submit(RawPacket::Ip(
                        IpHdr::V4(header),
                        ProtoHdr::Tcp(unsafe { *tcphdr }),
                    ));
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = u16::from_be(unsafe { (*udphdr).source });
                    let dst_port = u16::from_be(unsafe { (*udphdr).dest });

                    if filter_for_ipv4_address(src_addr, src_port, &BLOCKLIST_IPV4)
                        || filter_for_ipv4_address(dst_addr, dst_port, &BLOCKLIST_IPV4)
                    {
                        return Ok(TC_ACT_SHOT);
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv4))
                        || filter_packet(Protocol::Transport(TransportProtocol::UDP))
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    submit(RawPacket::Ip(
                        IpHdr::V4(header),
                        ProtoHdr::Udp(unsafe { *udphdr }),
                    ));
                }
                IpProto::Icmp => {
                    if filter_packet(Protocol::Network(NetworkProtocol::Icmp)) {
                        return Ok(TC_ACT_PIPE);
                    }
                    let icmphdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V4(header),
                        ProtoHdr::Icmp(unsafe { *icmphdr }),
                    ));
                }
                _ => {}
            }
        }
        EtherType::Ipv6 => {
            let header: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let src_addr = header.src_addr().to_bits();
            let dst_addr = header.dst_addr().to_bits();

            match header.next_hdr {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    let src_port = u16::from_be(unsafe { (*tcphdr).source });
                    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

                    if filter_for_ipv6_address(src_addr, src_port, &BLOCKLIST_IPV6)
                        || filter_for_ipv6_address(dst_addr, dst_port, &BLOCKLIST_IPV6)
                    {
                        return Ok(TC_ACT_SHOT);
                    }
                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv6))
                        || filter_packet(Protocol::Transport(TransportProtocol::TCP))
                    {
                        return Ok(TC_ACT_PIPE); //DONT FWD PACKET TO TUI
                    }
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Tcp(unsafe { *tcphdr }),
                    ));
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    let src_port = u16::from_be(unsafe { (*udphdr).source });
                    let dst_port = u16::from_be(unsafe { (*udphdr).dest });

                    if filter_for_ipv6_address(src_addr, src_port, &BLOCKLIST_IPV6)
                        || filter_for_ipv6_address(dst_addr, dst_port, &BLOCKLIST_IPV6)
                    {
                        return Ok(TC_ACT_SHOT);
                    }
                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv6))
                        || filter_packet(Protocol::Transport(TransportProtocol::UDP))
                    {
                        return Ok(TC_ACT_PIPE); //DONT FWD PACKET TO TUI
                    }
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Udp(unsafe { *udphdr }),
                    ));
                }
                IpProto::Icmp => {
                    if filter_packet(Protocol::Network(NetworkProtocol::Icmp)) {
                        return Ok(TC_ACT_PIPE);
                    }
                    let icmphdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Icmp(unsafe { *icmphdr }),
                    ));
                }
                _ => {}
            }
        }
        EtherType::Arp => {
            if filter_packet(Protocol::Link(LinkProtocol::Arp)) {
                return Ok(TC_ACT_PIPE);
            }
            let header: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            submit(RawPacket::Arp(header));
        }
        _ => {}
    };

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
