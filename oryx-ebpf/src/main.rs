#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
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
use oryx_common::{ip::ProtoHdr, RawPacket};

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
fn process(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let header: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            match header.proto {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V4(header),
                        ProtoHdr::Tcp(unsafe { *tcphdr }),
                    ));
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V4(header),
                        ProtoHdr::Udp(unsafe { *udphdr }),
                    ));
                }
                IpProto::Icmp => {
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
            match header.next_hdr {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Tcp(unsafe { *tcphdr }),
                    ));
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Udp(unsafe { *udphdr }),
                    ));
                }
                IpProto::Icmp => {
                    let icmphdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    submit(RawPacket::Ip(
                        IpHdr::V6(header),
                        ProtoHdr::Icmp(unsafe { *icmphdr }),
                    ));
                }
                _ => {}
            }
        }
        EtherType::Arp => {
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
