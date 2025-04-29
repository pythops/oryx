use std::{
    net::IpAddr,
    os::fd::AsRawFd,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};

use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap},
    programs::{tc, SchedClassifier, TcAttachType},
    EbpfLoader,
};
use log::error;
use oryx_common::{protocols::Protocol, RawPacket, MAX_RULES_PORT};

use crate::{
    event::Event,
    filter::FilterChannelSignal,
    notification::{Notification, NotificationLevel},
    packet::direction::TrafficDirection,
    section::firewall::FirewallSignal,
};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};

use super::{
    firewall::{update_ipv4_blocklist, update_ipv6_blocklist},
    EbpfTrafficDirection, RingBuffer,
};

pub fn load_ingress(
    iface: String,
    notification_sender: kanal::Sender<Event>,
    data_sender: kanal::Sender<([u8; RawPacket::LEN], TrafficDirection)>,
    filter_channel_receiver: kanal::Receiver<FilterChannelSignal>,
    firewall_ingress_receiver: kanal::Receiver<FirewallSignal>,
    terminate: Arc<AtomicBool>,
) {
    thread::spawn({
        let iface = iface.to_owned();
        let notification_sender = notification_sender.clone();

        move || {
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };

            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

            let traffic_direction = EbpfTrafficDirection::Ingress as i32;

            #[cfg(debug_assertions)]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &traffic_direction, true)
                .load(include_bytes_aligned!(env!("ORYX_BIN_PATH")))
            {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to load the ingress eBPF bytecode. {}", e);
                    Notification::send(
                        "Failed to load the ingress eBPF bytecode",
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            #[cfg(not(debug_assertions))]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &traffic_direction, true)
                .load(include_bytes_aligned!(env!("ORYX_BIN_PATH")))
            {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to load the ingress eBPF bytecode. {}", e);
                    Notification::send(
                        "Failed to load the ingress eBPF bytecode",
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            let _ = tc::qdisc_add_clsact(&iface);

            let program: &mut SchedClassifier =
                bpf.program_mut("oryx").unwrap().try_into().unwrap();

            if let Err(e) = program.load() {
                error!(
                    "Failed to load the ingress eBPF program to the kernel. {}",
                    e
                );
                Notification::send(
                    "Failed to load the ingress eBPF program to the kernel",
                    NotificationLevel::Error,
                    notification_sender,
                )
                .unwrap();
                return;
            };

            if let Err(e) = program.attach(&iface, TcAttachType::Ingress) {
                error!(
                    "Failed to attach the ingress eBPF program to the interface. {}",
                    e
                );
                Notification::send(
                    "Failed to attach the ingress eBPF program to the interface",
                    NotificationLevel::Error,
                    notification_sender,
                )
                .unwrap();
                return;
            };

            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(128);

            //filter-ebpf interface
            let mut transport_filters: Array<_, u32> =
                Array::try_from(bpf.take_map("TRANSPORT_FILTERS").unwrap()).unwrap();

            let mut network_filters: Array<_, u32> =
                Array::try_from(bpf.take_map("NETWORK_FILTERS").unwrap()).unwrap();

            let mut link_filters: Array<_, u32> =
                Array::try_from(bpf.take_map("LINK_FILTERS").unwrap()).unwrap();

            let mut traffic_direction_filter: Array<_, u8> =
                Array::try_from(bpf.take_map("TRAFFIC_DIRECTION_FILTER").unwrap()).unwrap();

            // firewall-ebpf interface
            let mut ipv4_firewall: HashMap<_, u32, [u16; MAX_RULES_PORT]> =
                HashMap::try_from(bpf.take_map("BLOCKLIST_IPV4").unwrap()).unwrap();

            let mut ipv6_firewall: HashMap<_, u128, [u16; MAX_RULES_PORT]> =
                HashMap::try_from(bpf.take_map("BLOCKLIST_IPV6").unwrap()).unwrap();

            // firewall thread
            thread::spawn(move || loop {
                if let Ok(signal) = firewall_ingress_receiver.recv() {
                    match signal {
                        FirewallSignal::Rule(rule) => match rule.ip {
                            IpAddr::V4(addr) => update_ipv4_blocklist(
                                &mut ipv4_firewall,
                                addr,
                                rule.port,
                                rule.enabled,
                            ),

                            IpAddr::V6(addr) => update_ipv6_blocklist(
                                &mut ipv6_firewall,
                                addr,
                                rule.port,
                                rule.enabled,
                            ),
                        },
                        FirewallSignal::Kill => {
                            break;
                        }
                    }
                }
            });

            // packets filters thread
            thread::spawn(move || loop {
                if let Ok(signal) = filter_channel_receiver.recv() {
                    match signal {
                        FilterChannelSignal::ProtoUpdate((filter, flag)) => match filter {
                            Protocol::Transport(p) => {
                                let _ = transport_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Network(p) => {
                                let _ = network_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Link(p) => {
                                let _ = link_filters.set(p as u32, flag as u32, 0);
                            }
                        },
                        FilterChannelSignal::DirectionUpdate(flag) => {
                            let _ = traffic_direction_filter.set(0, flag as u8, 0);
                        }
                        FilterChannelSignal::Kill => {
                            break;
                        }
                    }
                }
            });

            // packets reader
            let mut ring_buf = RingBuffer::new(&mut bpf);

            poll.registry()
                .register(
                    &mut SourceFd(&ring_buf.buffer.as_raw_fd()),
                    Token(0),
                    Interest::READABLE,
                )
                .unwrap();

            loop {
                poll.poll(&mut events, Some(Duration::from_millis(100)))
                    .unwrap();
                if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                for event in &events {
                    if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    if event.token() == Token(0) && event.is_readable() {
                        if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        while let Some(item) = ring_buf.next() {
                            if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }
                            let packet: [u8; RawPacket::LEN] = item.to_owned().try_into().unwrap();
                            data_sender.send((packet, TrafficDirection::Ingress)).ok();
                        }
                    }
                }
            }

            let _ = poll
                .registry()
                .deregister(&mut SourceFd(&ring_buf.buffer.as_raw_fd()));
        }
    });
}
