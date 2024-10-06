use std::{
    io,
    net::IpAddr,
    os::fd::AsRawFd,
    sync::{atomic::AtomicBool, Arc},
    thread::{self, spawn},
    time::Duration,
};

use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBufItem, Array, HashMap, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
    Bpf,
};
use oryx_common::{protocols::Protocol, RawPacket};

use crate::{
    event::Event,
    notification::{Notification, NotificationLevel},
    section::firewall::FirewallRule,
};
use mio::{event::Source, unix::SourceFd, Events, Interest, Poll, Registry, Token};

pub struct Ebpf;

pub struct RingBuffer<'a> {
    buffer: RingBuf<&'a mut MapData>,
}

impl<'a> RingBuffer<'a> {
    fn new(bpf: &'a mut Bpf) -> Self {
        let buffer = RingBuf::try_from(bpf.map_mut("DATA").unwrap()).unwrap();
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

impl Ebpf {
    pub fn load_ingress(
        iface: String,
        notification_sender: kanal::Sender<Event>,
        data_sender: kanal::Sender<[u8; RawPacket::LEN]>,
        filter_channel_receiver: kanal::Receiver<(Protocol, bool)>,
        firewall_ingress_receiver: kanal::Receiver<FirewallRule>,
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
                let mut bpf = match Bpf::load(include_bytes_aligned!(
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
                let mut bpf = match Bpf::load(include_bytes_aligned!(
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
                // firewall-ebpf interface
                let mut ipv4_firewall: HashMap<_, u32, u16> =
                    HashMap::try_from(bpf.take_map("BLOCKLIST_IPV4_INGRESS").unwrap()).unwrap();
                let mut ipv6_firewall: HashMap<_, u128, u16> =
                    HashMap::try_from(bpf.take_map("BLOCKLIST_IPV6_INGRESS").unwrap()).unwrap();

                spawn(move || loop {
                    if let Ok(rule) = firewall_ingress_receiver.recv() {
                        match rule.enabled {
                            true => match rule.ip {
                                IpAddr::V4(addr) => {
                                    println!("{}", rule);
                                    ipv4_firewall.insert(u32::from(addr), rule.port, 0).unwrap();
                                }
                                IpAddr::V6(addr) => {
                                    let _ = ipv6_firewall.insert(
                                        u128::from_be_bytes(addr.octets()),
                                        rule.port,
                                        0,
                                    );
                                }
                            },

                            false => match rule.ip {
                                IpAddr::V4(addr) => {
                                    let _ = ipv4_firewall.remove(&u32::from(addr));
                                }

                                IpAddr::V6(addr) => {
                                    let _ =
                                        ipv6_firewall.remove(&u128::from_be_bytes(addr.octets()));
                                }
                            },
                        }
                    }

                    if let Ok((filter, flag)) = filter_channel_receiver.recv() {
                        match filter {
                            Protocol::Transport(p) => {
                                let _ = transport_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Network(p) => {
                                let _ = network_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Link(p) => {
                                let _ = link_filters.set(p as u32, flag as u32, 0);
                            }
                        }
                    }
                });

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
                                let packet: [u8; RawPacket::LEN] =
                                    item.to_owned().try_into().unwrap();
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
        filter_channel_receiver: kanal::Receiver<(Protocol, bool)>,
        _firewall_channel_receiver: kanal::Receiver<(Protocol, bool)>,
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
                let mut bpf = match Bpf::load(include_bytes_aligned!(
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
                let mut bpf = match Bpf::load(include_bytes_aligned!(
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

                let mut transport_filters: Array<_, u32> =
                    Array::try_from(bpf.take_map("TRANSPORT_FILTERS").unwrap()).unwrap();

                let mut network_filters: Array<_, u32> =
                    Array::try_from(bpf.take_map("NETWORK_FILTERS").unwrap()).unwrap();

                let mut link_filters: Array<_, u32> =
                    Array::try_from(bpf.take_map("LINK_FILTERS").unwrap()).unwrap();

                spawn(move || loop {
                    if let Ok((filter, flag)) = filter_channel_receiver.recv() {
                        match filter {
                            Protocol::Transport(p) => {
                                let _ = transport_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Network(p) => {
                                let _ = network_filters.set(p as u32, flag as u32, 0);
                            }
                            Protocol::Link(p) => {
                                let _ = link_filters.set(p as u32, flag as u32, 0);
                            }
                        }
                    }
                });
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
                                let packet: [u8; RawPacket::LEN] =
                                    item.to_owned().try_into().unwrap();
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
}
