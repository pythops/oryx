use std::fs::File;

use aya::programs::{links::CgroupAttachMode, CgroupSock, CgroupSockAddr};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};

use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/test-sockaddr"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let file = File::open("/sys/fs/cgroup/user.slice")?;
    let sock_create: &mut CgroupSock = ebpf.program_mut("socket_create").unwrap().try_into()?;
    sock_create.load()?;
    sock_create.attach(file, CgroupAttachMode::Single)?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/test-sockaddr"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let sock_connect: &mut CgroupSockAddr =
        ebpf.program_mut("socket_connect").unwrap().try_into()?;
    sock_connect.load()?;
    let file = File::open("/sys/fs/cgroup/user.slice")?;

    sock_connect.attach(file, CgroupAttachMode::Single)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
