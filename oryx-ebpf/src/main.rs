#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};

use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
};
use oryx_common::RawPacket;

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
fn process(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let header: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            match header.proto {
                IpProto::Tcp | IpProto::Udp | IpProto::Icmp => {
                    submit(RawPacket::Ip(IpHdr::V4(header)));
                }
                _ => {}
            }
        }
        EtherType::Ipv6 => {
            let header: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            match header.next_hdr {
                IpProto::Tcp | IpProto::Udp | IpProto::Icmp => {
                    submit(RawPacket::Ip(IpHdr::V6(header)));
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
