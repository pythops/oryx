use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use aya::maps::ring_buf::RingBufItem;
use aya::maps::{MapData, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use mio::{Events, Interest, Poll, Registry, Token};
use oryx_common::IpPacket;

use crate::event::Event;
use mio::event::Source;
use mio::unix::SourceFd;

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
    pub fn load_ingress(iface: String, sender: kanal::Sender<Event>, terminate: Arc<AtomicBool>) {
        thread::spawn({
            let iface = iface.to_owned();
            let sender = sender.clone();

            move || {
                let rlim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };

                unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

                #[cfg(debug_assertions)]
                let mut bpf = Bpf::load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/debug/oryx"
                ))
                .unwrap();

                #[cfg(not(debug_assertions))]
                let mut bpf = Bpf::load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/release/oryx"
                ))
                .unwrap();

                let _ = tc::qdisc_add_clsact(&iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("oryx").unwrap().try_into().unwrap();
                program.load().unwrap();

                program.attach(&iface, TcAttachType::Ingress).unwrap();

                let mut poll = Poll::new().unwrap();
                let mut events = Events::with_capacity(128);

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
                                let packet: [u8; 40] = item.to_owned().try_into().unwrap();
                                sender.send(Event::Packet(IpPacket::from(packet))).ok();
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

    pub fn load_egress(iface: String, sender: kanal::Sender<Event>, terminate: Arc<AtomicBool>) {
        thread::spawn({
            let iface = iface.to_owned();
            let sender = sender.clone();

            move || {
                let rlim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };

                unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

                #[cfg(debug_assertions)]
                let mut bpf = Bpf::load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/debug/oryx"
                ))
                .unwrap();

                #[cfg(not(debug_assertions))]
                let mut bpf = Bpf::load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/release/oryx"
                ))
                .unwrap();

                let _ = tc::qdisc_add_clsact(&iface);
                let program: &mut SchedClassifier =
                    bpf.program_mut("oryx").unwrap().try_into().unwrap();
                program.load().unwrap();

                program.attach(&iface, TcAttachType::Egress).unwrap();

                let mut poll = Poll::new().unwrap();
                let mut events = Events::with_capacity(128);

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
                                let packet: [u8; 40] = item.to_owned().try_into().unwrap();
                                sender.send(Event::Packet(IpPacket::from(packet))).ok();
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
