use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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
    section::firewall::{BlockedPort, FirewallRule},
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

fn update_ipv4_blocklist(
    ipv4_firewall: &mut HashMap<MapData, u32, [u16; 32]>,
    addr: Ipv4Addr,
    port: BlockedPort,
    enabled: bool,
) {
    // hashmap entry exists
    if let Ok(mut blocked_ports) = ipv4_firewall.get(&addr.to_bits(), 0) {
        match port {
            // single port update
            BlockedPort::Single(port) => {
                if enabled {
                    // add port to blocklist
                    if let Some(first_zero) = blocked_ports.iter().enumerate().find(|&x| *x.1 == 0)
                    {
                        blocked_ports[first_zero.0] = port;
                        // dbg!("UPSERTING");
                        // dbg!(blocked_ports[0], blocked_ports[1]);
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        todo!(); // list is full
                    }
                } else {
                    //  remove port from blocklist
                    // eg: remove port 53 [8888,53,80,0,..] => [8888,0,80,0,..] => [8888,80,0 ....]
                    let non_null_ports = blocked_ports
                        .into_iter()
                        .filter(|p| (*p != 0 && *p != port))
                        .collect::<Vec<u16>>();
                    let mut blocked_ports = [0; 32];
                    for (idx, p) in non_null_ports.iter().enumerate() {
                        blocked_ports[idx] = *p;
                    }
                    if blocked_ports.iter().sum::<u16>() == 0 {
                        //if block_list is now empty, we need to delete key
                        ipv4_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if enabled {
                    ipv4_firewall.insert(addr.to_bits(), [0; 32], 0).unwrap();
                } else {
                    ipv4_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if enabled {
        let mut blocked_ports: [u16; 32] = [0; 32];
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
    ipv6_firewall: &mut HashMap<MapData, u128, [u16; 32]>,
    addr: Ipv6Addr,
    port: BlockedPort,
    enabled: bool,
) {
    // hashmap entry exists
    if let Ok(mut blocked_ports) = ipv6_firewall.get(&addr.to_bits(), 0) {
        match port {
            // single port update
            BlockedPort::Single(port) => {
                if enabled {
                    // add port to blocklist
                    if let Some(first_zero) = blocked_ports.iter().enumerate().find(|&x| *x.1 == 0)
                    {
                        blocked_ports[first_zero.0] = port;
                        // dbg!("UPSERTING");
                        // dbg!(blocked_ports[0], blocked_ports[1]);
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        todo!(); // list is full
                    }
                } else {
                    //  remove port from blocklist
                    // eg: remove port 53 [8888,53,80,0,..] => [8888,0,80,0,..] => [8888,80,0 ....]
                    let non_null_ports = blocked_ports
                        .into_iter()
                        .filter(|p| (*p != 0 && *p != port))
                        .collect::<Vec<u16>>();
                    let mut blocked_ports = [0; 32];
                    for (idx, p) in non_null_ports.iter().enumerate() {
                        blocked_ports[idx] = *p;
                    }
                    if blocked_ports.iter().sum::<u16>() == 0 {
                        //if block_list is now empty, we need to delete key
                        ipv6_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if enabled {
                    ipv6_firewall.insert(addr.to_bits(), [0; 32], 0).unwrap();
                } else {
                    ipv6_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if enabled {
        let mut blocked_ports: [u16; 32] = [0; 32];
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
                let mut ipv4_firewall: HashMap<_, u32, [u16; 32]> =
                    HashMap::try_from(bpf.take_map("BLOCKLIST_IPV4_INGRESS").unwrap()).unwrap();
                let mut ipv6_firewall: HashMap<_, u128, [u16; 32]> =
                    HashMap::try_from(bpf.take_map("BLOCKLIST_IPV6_INGRESS").unwrap()).unwrap();

                thread::spawn(move || loop {
                    if let Ok(rule) = firewall_ingress_receiver.recv() {
                        match rule.ip {
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
                        }
                    }
                });

                thread::spawn(move || loop {
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
