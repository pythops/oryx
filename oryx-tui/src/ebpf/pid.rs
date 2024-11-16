use std::{
    fs::{self, File},
    os::fd::AsRawFd,
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
    time::Duration,
};

use aya::{
    include_bytes_aligned,
    programs::{CgroupAttachMode, CgroupSockAddr},
    EbpfLoader,
};
use log::error;

use crate::{
    event::Event,
    notification::{Notification, NotificationLevel},
    pid::ConnectionMap,
};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};

use super::RingBuffer;

pub fn load_pid(
    pid_map: Arc<Mutex<ConnectionMap>>,
    notification_sender: kanal::Sender<Event>,
    terminate: Arc<AtomicBool>,
) {
    thread::spawn({
        move || {
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };

            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

            #[cfg(debug_assertions)]
            let mut bpf = match EbpfLoader::new().load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/debug/oryx"
            )) {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to load the pid eBPF bytecode. {}", e);
                    Notification::send(
                        "Failed to load the pid eBPF bytecode",
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            #[cfg(not(debug_assertions))]
            let mut bpf = match EbpfLoader::new().load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/debug/oryx"
            )) {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to load the pid eBPF bytecode. {}", e);
                    Notification::send(
                        "Failed to load the pid eBPF bytecode",
                        NotificationLevel::Error,
                        notification_sender,
                    )
                    .unwrap();
                    return;
                }
            };

            let sock_connect: &mut CgroupSockAddr = bpf
                .program_mut("socket_connect")
                .unwrap()
                .try_into()
                .unwrap();
            sock_connect.load().unwrap();
            let file = File::open("/sys/fs/cgroup/user.slice").unwrap();

            sock_connect.attach(file, CgroupAttachMode::Single).unwrap();

            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(128);

            let mut ring_buf = RingBuffer::new(&mut bpf, "PID_DATA");

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
                            let pid: [u8; 4] = item.to_owned().try_into().unwrap();
                            let pid = u32::from_ne_bytes(pid);

                            let fd_dir = format!("/proc/{}/fd", pid);
                            if let Ok(_fds) = fs::read_dir(&fd_dir) {
                                let mut map = pid_map.lock().unwrap();
                                *map = ConnectionMap::new();
                            }
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
