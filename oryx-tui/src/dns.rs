use libc::{NI_MAXHOST, NI_NAMEREQD, c_char, getnameinfo, sockaddr_in, sockaddr_in6, socklen_t};
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::app::AppResult;

pub fn get_hostname(ip: &IpAddr) -> AppResult<String> {
    match ip {
        IpAddr::V4(v) => get_hostname_v4(v),
        IpAddr::V6(v) => get_hostname_v6(v),
    }
}

fn get_hostname_v4(ip: &Ipv4Addr) -> AppResult<String> {
    let sockaddr = sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };

    let mut host: [c_char; NI_MAXHOST as usize] = [0; NI_MAXHOST as usize];

    let result = unsafe {
        getnameinfo(
            &sockaddr as *const _ as *const _,
            mem::size_of::<sockaddr_in>() as socklen_t,
            host.as_mut_ptr(),
            NI_MAXHOST,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD,
        )
    };

    if result != 0 {
        return Err("Failed to get hostname".into());
    }

    let host_str = unsafe { CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned() };

    Ok(host_str)
}

fn get_hostname_v6(ip: &Ipv6Addr) -> AppResult<String> {
    let sockaddr = sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_flowinfo: 0,
        sin6_scope_id: 0,
    };

    let mut host: [c_char; NI_MAXHOST as usize] = [0; NI_MAXHOST as usize];

    let result = unsafe {
        getnameinfo(
            &sockaddr as *const _ as *const _,
            mem::size_of::<sockaddr_in6>() as socklen_t,
            host.as_mut_ptr(),
            NI_MAXHOST,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD,
        )
    };

    if result != 0 {
        return Err("Failed to get hostname".into());
    }

    let host_str = unsafe { CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned() };

    Ok(host_str)
}
