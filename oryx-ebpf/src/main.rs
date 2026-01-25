#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_get_current_pid_tgid,
    macros::{classifier, map},
    maps::{Array, HashMap, RingBuf},
    programs::TcContext,
};
use branches::unlikely;
use core::mem;
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    icmp::{Icmp, IcmpHdr, IcmpV6Hdr},
    igmp::{IGMPv1Hdr, IGMPv2Hdr, IGMPv3MembershipQueryHdr, IGMPv3MembershipReportHdr},
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    sctp::SctpHdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
use oryx_common::{
    IGMPv3Hdr, IgmpHdr, MAX_FIREWALL_RULES, MAX_RULES_PORT, ProtoHdr, RawData, RawFrame, RawPacket,
    protocols::{LinkProtocol, NetworkProtocol, Protocol, TransportProtocol},
};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * RawFrame::LEN as u32, 0);

#[map]
static NETWORK_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static TRANSPORT_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static LINK_FILTERS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static TRAFFIC_DIRECTION_FILTER: Array<u8> = Array::with_max_entries(1, 0);

#[map]
static BLOCKLIST_IPV6: HashMap<u128, [u16; MAX_RULES_PORT]> =
    HashMap::<u128, [u16; MAX_RULES_PORT]>::with_max_entries(MAX_FIREWALL_RULES, 0);

#[map]
static BLOCKLIST_IPV4: HashMap<u32, [u16; MAX_RULES_PORT]> =
    HashMap::<u32, [u16; MAX_RULES_PORT]>::with_max_entries(MAX_FIREWALL_RULES, 0);

#[unsafe(no_mangle)]
static PID_HELPER_AVAILABILITY: u8 = 0;

#[unsafe(no_mangle)]
static TRAFFIC_DIRECTION: i32 = 0;

#[classifier]
pub fn oryx(ctx: TcContext) -> i32 {
    match process(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn submit(data: RawData) {
    if let Some(mut buf) = DATA.reserve::<RawData>(0) {
        unsafe { (*buf.as_mut_ptr()) = data };
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
fn filter_direction() -> bool {
    // 0(default) -> false(send to tui), 1 -> true(filter)
    if let Some(v) = TRAFFIC_DIRECTION_FILTER.get(0) {
        return *v != 0;
    }
    false
}

#[inline]
fn is_ingress() -> bool {
    let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
    traffic_direction == -1
}

#[inline]
fn block_ipv4(addr: u32, port: u16) -> bool {
    if let Some(blocked_ports) = unsafe { BLOCKLIST_IPV4.get(&addr) } {
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
fn block_ipv6(addr: u128, port: u16) -> bool {
    if let Some(blocked_ports) = unsafe { BLOCKLIST_IPV6.get(&addr) } {
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
    let eth_header: *const EthHdr = ptr_at(&ctx, 0)?;

    let pid = if is_ingress() {
        None
    } else {
        let is_pid_helper_available = unsafe { core::ptr::read_volatile(&PID_HELPER_AVAILABILITY) };

        if is_pid_helper_available == 1 {
            Some((bpf_get_current_pid_tgid() >> 32) as u32)
        } else {
            None
        }
    };

    let ether_type = EtherType::try_from(unsafe { (*eth_header).ether_type }).map_err(|_| ())?;

    match ether_type {
        EtherType::Ipv4 => {
            let ipv4_header: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

            let addr = unsafe {
                if is_ingress() {
                    u32::from_be_bytes((*ipv4_header).src_addr)
                } else {
                    u32::from_be_bytes((*ipv4_header).dst_addr)
                }
            };

            match unsafe { (*ipv4_header).proto } {
                IpProto::Tcp => {
                    let tcp_header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    let port = if is_ingress() {
                        u16::from_be_bytes(unsafe { (*tcp_header).source })
                    } else {
                        u16::from_be_bytes(unsafe { (*tcp_header).dest })
                    };

                    if unlikely(block_ipv4(addr, port)) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv4))
                        || filter_packet(Protocol::Transport(TransportProtocol::TCP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V4(*ipv4_header),
                                    ProtoHdr::Tcp(*tcp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Udp => {
                    let udp_header: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    let port = if is_ingress() {
                        u16::from_be_bytes(unsafe { (*udp_header).src })
                    } else {
                        u16::from_be_bytes(unsafe { (*udp_header).dst })
                    };

                    if unlikely(block_ipv4(addr, port)) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv4))
                        || filter_packet(Protocol::Transport(TransportProtocol::UDP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V4(*ipv4_header),
                                    ProtoHdr::Udp(*udp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Sctp => {
                    let sctp_header: *const SctpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    let port = if is_ingress() {
                        u16::from_be_bytes(unsafe { (*sctp_header).src })
                    } else {
                        u16::from_be_bytes(unsafe { (*sctp_header).dst })
                    };

                    if unlikely(block_ipv4(addr, port)) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv4))
                        || filter_packet(Protocol::Transport(TransportProtocol::SCTP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V4(*ipv4_header),
                                    ProtoHdr::Sctp(*sctp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Icmp => {
                    if filter_packet(Protocol::Network(NetworkProtocol::Icmpv4)) {
                        return Ok(TC_ACT_PIPE);
                    }
                    let icmp_header: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V4(*ipv4_header),
                                    ProtoHdr::Icmp(Icmp::V4(*icmp_header)),
                                ),
                            },
                            pid,
                        });
                    }
                }

                IpProto::Igmp => {
                    if filter_packet(Protocol::Network(NetworkProtocol::Igmp)) {
                        return Ok(TC_ACT_PIPE);
                    }

                    let payload_length = unsafe {
                        u16::from_be_bytes((*ipv4_header).tot_len) - (*ipv4_header).ihl() as u16
                    };

                    let ihl: u8 = ctx.load(EthHdr::LEN).map_err(|_| ())?;
                    let ihl = (ihl & 0x0F) * 4;

                    let igmp_type: u8 = ctx.load(EthHdr::LEN + ihl as usize).map_err(|_| ())?;

                    match igmp_type {
                        0x11 => {
                            if payload_length == 8 {
                                // v1 or v2
                                let max_response_time: u8 =
                                    ctx.load(EthHdr::LEN + ihl as usize + 1).map_err(|_| ())?;

                                if max_response_time == 0 {
                                    //v1
                                    let igmp_header: *const IGMPv1Hdr =
                                        ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                                    unsafe {
                                        submit(RawData {
                                            frame: RawFrame {
                                                header: *eth_header,
                                                payload: RawPacket::Ip(
                                                    IpHdr::V4(*ipv4_header),
                                                    ProtoHdr::Igmp(IgmpHdr::V1(*igmp_header)),
                                                ),
                                            },
                                            pid,
                                        });
                                    }
                                } else {
                                    // v2
                                    let igmp_header: *const IGMPv2Hdr =
                                        ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                                    unsafe {
                                        submit(RawData {
                                            frame: RawFrame {
                                                header: *eth_header,
                                                payload: RawPacket::Ip(
                                                    IpHdr::V4(*ipv4_header),
                                                    ProtoHdr::Igmp(IgmpHdr::V2(*igmp_header)),
                                                ),
                                            },
                                            pid,
                                        });
                                    }
                                }
                            } else {
                                // v3
                                let igmp_header: *const IGMPv3MembershipQueryHdr =
                                    ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                                unsafe {
                                    submit(RawData {
                                        frame: RawFrame {
                                            header: *eth_header,
                                            payload: RawPacket::Ip(
                                                IpHdr::V4(*ipv4_header),
                                                ProtoHdr::Igmp(IgmpHdr::V3(IGMPv3Hdr::Query(
                                                    *igmp_header,
                                                ))),
                                            ),
                                        },
                                        pid,
                                    });
                                }
                            }
                        }
                        0x12 => {
                            let igmp_header: *const IGMPv1Hdr =
                                ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                            unsafe {
                                submit(RawData {
                                    frame: RawFrame {
                                        header: *eth_header,
                                        payload: RawPacket::Ip(
                                            IpHdr::V4(*ipv4_header),
                                            ProtoHdr::Igmp(IgmpHdr::V1(*igmp_header)),
                                        ),
                                    },
                                    pid,
                                });
                            }
                        }
                        0x16 | 0x17 => {
                            let igmp_header: *const IGMPv2Hdr =
                                ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                            unsafe {
                                submit(RawData {
                                    frame: RawFrame {
                                        header: *eth_header,
                                        payload: RawPacket::Ip(
                                            IpHdr::V4(*ipv4_header),
                                            ProtoHdr::Igmp(IgmpHdr::V2(*igmp_header)),
                                        ),
                                    },
                                    pid,
                                });
                            }
                        }
                        0x22 => {
                            let igmp_header: *const IGMPv3MembershipReportHdr =
                                ptr_at(&ctx, EthHdr::LEN + ihl as usize)?;

                            unsafe {
                                submit(RawData {
                                    frame: RawFrame {
                                        header: *eth_header,
                                        payload: RawPacket::Ip(
                                            IpHdr::V4(*ipv4_header),
                                            ProtoHdr::Igmp(IgmpHdr::V3(IGMPv3Hdr::Report(
                                                *igmp_header,
                                            ))),
                                        ),
                                    },
                                    pid,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        EtherType::Ipv6 => {
            let ipv6_header: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;

            let addr = unsafe {
                if is_ingress() {
                    (*ipv6_header).src_addr().to_bits()
                } else {
                    (*ipv6_header).dst_addr().to_bits()
                }
            };

            match unsafe { (*ipv6_header).next_hdr } {
                IpProto::Tcp => {
                    let tcp_header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    let port = unsafe {
                        if is_ingress() {
                            u16::from_be_bytes((*tcp_header).source)
                        } else {
                            u16::from_be_bytes((*tcp_header).dest)
                        }
                    };

                    if block_ipv6(addr, port) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv6))
                        || filter_packet(Protocol::Transport(TransportProtocol::TCP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V6(*ipv6_header),
                                    ProtoHdr::Tcp(*tcp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Udp => {
                    let udp_header: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    let port = unsafe {
                        if is_ingress() {
                            u16::from_be_bytes((*udp_header).src)
                        } else {
                            u16::from_be_bytes((*udp_header).dst)
                        }
                    };

                    if block_ipv6(addr, port) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv6))
                        || filter_packet(Protocol::Transport(TransportProtocol::UDP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V6(*ipv6_header),
                                    ProtoHdr::Udp(*udp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Sctp => {
                    let sctp_header: *const SctpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    let port = if is_ingress() {
                        u16::from_be_bytes(unsafe { (*sctp_header).src })
                    } else {
                        u16::from_be_bytes(unsafe { (*sctp_header).dst })
                    };

                    if block_ipv6(addr, port) {
                        return Ok(TC_ACT_SHOT); //block packet
                    }

                    if filter_packet(Protocol::Network(NetworkProtocol::Ipv6))
                        || filter_packet(Protocol::Transport(TransportProtocol::SCTP))
                        || filter_direction()
                    {
                        return Ok(TC_ACT_PIPE);
                    }

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V6(*ipv6_header),
                                    ProtoHdr::Sctp(*sctp_header),
                                ),
                            },
                            pid,
                        });
                    }
                }
                IpProto::Ipv6Icmp => {
                    if filter_packet(Protocol::Network(NetworkProtocol::Icmpv6)) {
                        return Ok(TC_ACT_PIPE);
                    }
                    let icmp_header: *const IcmpV6Hdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    unsafe {
                        submit(RawData {
                            frame: RawFrame {
                                header: *eth_header,
                                payload: RawPacket::Ip(
                                    IpHdr::V6(*ipv6_header),
                                    ProtoHdr::Icmp(Icmp::V6(*icmp_header)),
                                ),
                            },
                            pid,
                        });
                    }
                }
                _ => {}
            }
        }
        EtherType::Arp => {
            if filter_packet(Protocol::Link(LinkProtocol::Arp)) {
                return Ok(TC_ACT_PIPE);
            }

            let arp_header: *const ArpHdr = ptr_at(&ctx, EthHdr::LEN)?;

            unsafe {
                submit(RawData {
                    frame: RawFrame {
                        header: *eth_header,
                        payload: RawPacket::Arp(*arp_header),
                    },
                    pid,
                });
            }
        }
        _ => {}
    };

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
