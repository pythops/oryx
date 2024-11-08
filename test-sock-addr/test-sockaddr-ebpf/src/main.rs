#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{bpf_sock, bpf_sock_addr},
    helpers::bpf_get_current_pid_tgid,
    macros::{cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
};
use aya_log_ebpf::info;

#[cgroup_sock_addr(connect4)]
pub fn socket_connect(ctx: SockAddrContext) -> i32 {
    info!(&ctx, "connect");
    match sock_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cgroup_sock(post_bind4)]
pub fn socket_create(ctx: SockContext) -> i32 {
    info!(&ctx, "create");
    match sock_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn sock_create(ctx: SockContext) -> Result<i32, i32> {
    let sock = unsafe { *(ctx.sock as *const bpf_sock) };
    let proto = sock.protocol;
    let family = sock.family;
    let type_ = sock.type_;

    info!(
        &ctx,
        "create sock with proto :{}  fam {} type {}  ", proto, family, type_,
    );
    Ok(1)
}

// pub struct bpf_sock_addr {
//     pub user_family: __u32,
//     pub user_ip4: __u32,
//     pub user_ip6: [__u32; 4usize],
//     pub user_port: __u32,
//     pub family: __u32,
//     pub type_: __u32,
//     pub protocol: __u32,
//     pub msg_src_ip4: __u32,
//     pub msg_src_ip6: [__u32; 4usize],
//     pub __bindgen_anon_1: bpf_sock_addr__bindgen_ty_1,
// }
fn sock_connect(ctx: SockAddrContext) -> Result<i32, i32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let sock_addr = unsafe { *(ctx.sock_addr as *const bpf_sock_addr) };

    let family = sock_addr.family;
    let proto = sock_addr.protocol as u8;
    let ipv4 = sock_addr.user_ip4;

    let port = sock_addr.user_port;
    info!(
        &ctx,
        "pid:{} family:{} proto:{} ip:{} port:{} ",
        pid,
        family,
        proto,
        Ipv4Addr::from_bits(u32::from_be(ipv4)),
        u16::from_be(port as u16)
    );
    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
