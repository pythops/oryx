#![no_std]
#![no_main]

use core::mem;
use core::net::IpAddr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use oryx_common::{IcmpPacket, IcmpType, IpPacket, TcpPacket, UdpPacket};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096 * 40, 0);

#[classifier]
pub fn oryx(ctx: TcContext) -> i32 {
    match process(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
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
fn parse_ipv4_packet(ctx: &TcContext) -> Result<IpPacket, ()> {
    let header: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    let dst_ip: IpAddr = header.dst_addr().into();

    let src_ip: IpAddr = header.src_addr().into();

    match header.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port = u16::from_be(unsafe { (*tcphdr).source });
            let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

            let packet = TcpPacket {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            };

            Ok(IpPacket::Tcp(packet))
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port = u16::from_be(unsafe { (*udphdr).source });
            let dst_port = u16::from_be(unsafe { (*udphdr).dest });
            let packet = UdpPacket {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            };

            Ok(IpPacket::Udp(packet))
        }
        IpProto::Icmp => {
            let icmp_header: *const IcmpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let icmp_type = u8::from_be(unsafe { (*icmp_header).type_ });
            let icmp_type = match icmp_type {
                0 => IcmpType::EchoReply,
                3 => IcmpType::DestinationUnreachable,
                8 => IcmpType::EchoRequest,
                _ => return Err(()),
            };

            let packet = IcmpPacket {
                src_ip,
                dst_ip,
                icmp_type,
            };
            Ok(IpPacket::Icmp(packet))
        }
        _ => Err(()),
    }
}

#[inline]
fn parse_ipv6_packet(ctx: &TcContext) -> Result<IpPacket, ()> {
    let header: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    let dst_ip: IpAddr = header.dst_addr().into();
    let src_ip: IpAddr = header.src_addr().into();

    match header.next_hdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            Ok(IpPacket::Tcp(TcpPacket {
                src_ip,
                dst_ip,
                src_port: u16::from_be(unsafe { (*tcphdr).source }),
                dst_port: u16::from_be(unsafe { (*tcphdr).dest }),
            }))
        }

        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            Ok(IpPacket::Udp(UdpPacket {
                src_ip,
                dst_ip,
                src_port: u16::from_be(unsafe { (*udphdr).source }),
                dst_port: u16::from_be(unsafe { (*udphdr).source }),
            }))
        }

        IpProto::Ipv6Icmp => {
            let icmp_header: *const IcmpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            let icmp_type = match u8::from_be(unsafe { (*icmp_header).type_ }) {
                129 => IcmpType::EchoReply,
                1 => IcmpType::DestinationUnreachable,
                128 => IcmpType::EchoRequest,
                _ => return Err(()),
            };

            Ok(IpPacket::Icmp(IcmpPacket {
                src_ip,
                dst_ip,
                icmp_type,
            }))
        }
        _ => Err(()),
    }
}

#[inline]
fn submit(packet: IpPacket) {
    if let Some(mut buf) = DATA.reserve::<IpPacket>(0) {
        unsafe { (*buf.as_mut_ptr()) = packet };
        buf.submit(0);
    }
}

#[inline]
fn process(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            submit(parse_ipv4_packet(&ctx)?);
        }
        EtherType::Ipv6 => {
            submit(parse_ipv6_packet(&ctx)?);
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
