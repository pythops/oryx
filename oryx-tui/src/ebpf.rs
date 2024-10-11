use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};

use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBufItem, Array, HashMap, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf, EbpfLoader,
};
use oryx_common::{protocols::Protocol, RawPacket, MAX_RULES_PORT};

use crate::{
    event::Event,
    filter::FilterChannelSignal,
    notification::{Notification, NotificationLevel},
    section::firewall::{BlockedPort, FirewallSignal},
};
use mio::{event::Source, unix::SourceFd, Events, Interest, Poll, Registry, Token};

pub struct RingBuffer<'a> {
    buffer: RingBuf<&'a mut MapData>,
}

impl<'a> RingBuffer<'a> {
    fn new(ebpf: &'a mut Ebpf) -> Self {
        let buffer = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        Self { buffer }
    }

    fn next(&mut self) -> Option<RingBufItem<'_>> {
        self.buffer.next()
    }
}

impl Source for RingBuffer<'_> {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).deregister(registry)
    }
}

fn update_ipv4_blocklist(
    ipv4_firewall: &mut HashMap<MapData, u32, [u16; MAX_RULES_PORT]>,
    addr: Ipv4Addr,
    port: BlockedPort,
    to_insert: bool,
) {
    if let Ok(mut blocked_ports) = ipv4_firewall.get(&addr.to_bits(), 0) {
        match port {
            BlockedPort::Single(port) => {
                if to_insert {
                    if let Some((first_zero_index, _)) = blocked_ports
                        .iter()
                        .enumerate()
                        .find(|(_, &value)| value == 0)
                    {
                        blocked_ports[first_zero_index] = port;
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        unreachable!();
                    }
                } else {
                    let not_null_ports = blocked_ports
                        .into_iter()
                        .filter(|p| (*p != 0 && *p != port))
                        .collect::<Vec<u16>>();

                    let mut blocked_ports = [0; MAX_RULES_PORT];

                    for (idx, p) in not_null_ports.iter().enumerate() {
                        blocked_ports[idx] = *p;
                    }

                    if blocked_ports.iter().all(|&port| port == 0) {
                        ipv4_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if to_insert {
                    ipv4_firewall
                        .insert(addr.to_bits(), [0; MAX_RULES_PORT], 0)
                        .unwrap();
                } else {
                    ipv4_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if to_insert {
        let mut blocked_ports: [u16; MAX_RULES_PORT] = [0; MAX_RULES_PORT];
        match port {
            BlockedPort::Single(port) => {
                blocked_ports[0] = port;
            }
            BlockedPort::All => {}
        }

        ipv4_firewall
            .insert(addr.to_bits(), blocked_ports, 0)
            .unwrap();
    }
}

fn update_ipv6_blocklist(
    ipv6_firewall: &mut HashMap<MapData, u128, [u16; MAX_RULES_PORT]>,
    addr: Ipv6Addr,
    port: BlockedPort,
    to_insert: bool,
) {
    if let Ok(mut blocked_ports) = ipv6_firewall.get(&addr.to_bits(), 0) {
        match port {
            BlockedPort::Single(port) => {
                if to_insert {
                    if let Some((first_zero_index, _)) = blocked_ports
                        .iter()
                        .enumerate()
                        .find(|(_, &value)| value == 0)
                    {
                        blocked_ports[first_zero_index] = port;
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        //TODO:
                        unreachable!(); // list is full
                    }
                } else {
                    let not_null_ports = blocked_ports
                        .into_iter()
                        .filter(|p| (*p != 0 && *p != port))
                        .collect::<Vec<u16>>();

                    let mut blocked_ports = [0; MAX_RULES_PORT];

                    for (idx, p) in not_null_ports.iter().enumerate() {
                        blocked_ports[idx] = *p;
                    }

                    if blocked_ports.iter().all(|&port| port == 0) {
                        ipv6_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if to_insert {
                    ipv6_firewall
                        .insert(addr.to_bits(), [0; MAX_RULES_PORT], 0)
                        .unwrap();
                } else {
                    ipv6_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if to_insert {
        let mut blocked_ports: [u16; MAX_RULES_PORT] = [0; MAX_RULES_PORT];
        match port {
            BlockedPort::Single(port) => {
                blocked_ports[0] = port;
            }
            BlockedPort::All => {}
        }

        ipv6_firewall
            .insert(addr.to_bits(), blocked_ports, 0)
            .unwrap();
    }
}

pub fn load_ingress(
    iface: String,
    notification_sender: kanal::Sender<Event>,
    data_sender: kanal::Sender<[u8; RawPacket::LEN]>,
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

            #[cfg(debug_assertions)]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &-1i32, true)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/debug/oryx"
                )) {
                Ok(v) => v,
                Err(e) => {
                    Notification::send(
                        format!("Failed to load the ingress eBPF bytecode\n {}", e),
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            #[cfg(not(debug_assertions))]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &(-1 as i32), true)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/release/oryx"
                )) {
                Ok(v) => v,
                Err(e) => {
                    Notification::send(
                        format!("Failed to load the ingress eBPF bytecode\n {}", e),
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
                Notification::send(
                    format!(
                        "Failed to load the ingress eBPF program to the kernel\n{}",
                        e
                    ),
                    NotificationLevel::Error,
                    notification_sender,
                )
                .unwrap();
                return;
            };

            if let Err(e) = program.attach(&iface, TcAttachType::Ingress) {
                Notification::send(
                    format!(
                        "Failed to attach the ingress eBPF program to the interface\n{}",
                        e
                    ),
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
                            data_sender.send(packet).ok();
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

pub fn load_egress(
    iface: String,
    notification_sender: kanal::Sender<Event>,
    data_sender: kanal::Sender<[u8; RawPacket::LEN]>,
    filter_channel_receiver: kanal::Receiver<FilterChannelSignal>,
    firewall_egress_receiver: kanal::Receiver<FirewallSignal>,
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

            #[cfg(debug_assertions)]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &1i32, true)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/debug/oryx"
                )) {
                Ok(v) => v,
                Err(e) => {
                    Notification::send(
                        format!("Fail to load the egress eBPF bytecode\n {}", e),
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            #[cfg(not(debug_assertions))]
            let mut bpf = match EbpfLoader::new()
                .set_global("TRAFFIC_DIRECTION", &(1 as i32), true)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/release/oryx"
                )) {
                Ok(v) => v,
                Err(e) => {
                    Notification::send(
                        format!("Failed to load the egress eBPF bytecode\n {}", e),
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
                Notification::send(
                    format!("Fail to load the egress eBPF program to the kernel\n{}", e),
                    NotificationLevel::Error,
                    notification_sender,
                )
                .unwrap();
                return;
            };

            if let Err(e) = program.attach(&iface, TcAttachType::Egress) {
                Notification::send(
                    format!(
                        "Failed to attach the egress eBPF program to the interface\n{}",
                        e
                    ),
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
                if let Ok(signal) = firewall_egress_receiver.recv() {
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

            // packets reading
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
                            data_sender.send(packet).ok();
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
