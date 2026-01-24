use std::{
    ffi::CString,
    fs::{OpenOptions, create_dir},
    io::prelude::*,
    os::unix::fs::chown,
    path::PathBuf,
};

use chrono::Local;

use crate::{
    packet::{
        NetworkPacket,
        network::{IpPacket, ip::IpProto},
    },
    packet_store::PacketStore,
};

use anyhow::{Result, bail};

pub fn export(packets: &PacketStore) -> Result<()> {
    let local_date = Local::now().format("%Y-%m-%d_%H-%M");

    let user = match std::env::var("SUDO_USER") {
        Ok(user) => user,
        Err(std::env::VarError::NotPresent) => String::from("root"),
        Err(e) => bail!(e),
    };

    let (uid, gid) = unsafe {
        let user = CString::new(user.clone()).unwrap();
        let passwd_ptr = libc::getpwnam(user.as_ptr());
        if passwd_ptr.is_null() {
            bail!("");
        } else {
            ((*passwd_ptr).pw_uid, (*passwd_ptr).pw_gid)
        }
    };

    let oryx_export_dir = match uid {
        0 => PathBuf::from("/root/oryx"),
        _ => PathBuf::from(format!("/home/{user}/oryx")),
    };

    if !oryx_export_dir.exists() {
        create_dir(&oryx_export_dir)?;
        chown(&oryx_export_dir, Some(uid), Some(gid))?;
    }

    let oryx_export_file = oryx_export_dir.join(format!("capture-{local_date}"));

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&oryx_export_file)
        .unwrap();
    chown(oryx_export_file, Some(uid), Some(uid))?;

    let headers = (
        "Src Ip", "Src Port", "Dst Ip", "Dst Port", "Protocol", "Pid", "Date",
    );
    writeln!(
        file,
        "{:39}  {:11}  {:39}  {:11}  {:8}    {:10}  {:10}\n",
        headers.0, headers.1, headers.2, headers.3, headers.4, headers.5, headers.6
    )?;
    packets.for_each(|app_packet| {
        let pid = if let Some(pid) = app_packet.pid {
            pid.to_string()
        } else {
            "-".to_string()
        };

        let date = app_packet.timestamp.format("%Y-%m-%d %H:%M:%S");

        match app_packet.frame.payload {
            NetworkPacket::Arp(p) => {
                writeln!(
                    file,
                    "{:39}  {:^11}  {:39}  {:^11}  {:10}  {:10}  {:10}",
                    p.src_mac.to_string(),
                    "-",
                    p.dst_mac.to_string(),
                    "-",
                    "ARP",
                    pid,
                    date
                )?;
            }
            NetworkPacket::Ip(packet) => match packet {
                IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                    IpProto::Tcp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv4_packet.src_ip,
                            p.src_port,
                            ipv4_packet.dst_ip,
                            p.dst_port,
                            "TCP",
                            pid,
                            date,
                        )?;
                    }
                    IpProto::Udp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv4_packet.src_ip,
                            p.src_port,
                            ipv4_packet.dst_ip,
                            p.dst_port,
                            "UDP",
                            pid,
                            date
                        )?;
                    }
                    IpProto::Sctp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv4_packet.src_ip,
                            p.src_port,
                            ipv4_packet.dst_ip,
                            p.dst_port,
                            "SCTP",
                            pid,
                            date
                        )?;
                    }
                    IpProto::Icmp(_) => {
                        writeln!(
                            file,
                            "{:39}  {:^11}  {:39}  {:^11}  {:10}  {:10}  {:10}",
                            ipv4_packet.src_ip, "-", ipv4_packet.dst_ip, "-", "ICMPv4", pid, date
                        )?;
                    }
                    IpProto::Igmp(_) => {
                        writeln!(
                            file,
                            "{:39}  {:^11}  {:39}  {:^11}  {:10}  {:10}  {:10}",
                            ipv4_packet.src_ip, "-", ipv4_packet.dst_ip, "-", "IGMP", pid, date
                        )?;
                    }
                },
                IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                    IpProto::Tcp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv6_packet.src_ip,
                            p.src_port,
                            ipv6_packet.dst_ip,
                            p.dst_port,
                            "TCP",
                            pid,
                            date
                        )?;
                    }
                    IpProto::Udp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv6_packet.src_ip,
                            p.src_port,
                            ipv6_packet.dst_ip,
                            p.dst_port,
                            "UDP",
                            pid,
                            date
                        )?;
                    }
                    IpProto::Sctp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  {:10}  {:10}  {:10}",
                            ipv6_packet.src_ip,
                            p.src_port,
                            ipv6_packet.dst_ip,
                            p.dst_port,
                            "SCTP",
                            pid,
                            date
                        )?;
                    }
                    IpProto::Icmp(_) => {
                        writeln!(
                            file,
                            "{:39}  {:^11}  {:39}  {:^11}  {:10}  {:10}  {:10}",
                            ipv6_packet.src_ip, "-", ipv6_packet.dst_ip, "-", "ICMPv6", pid, date
                        )?;
                    }
                    IpProto::Igmp(_) => {
                        //IGMP is for IPv4 only
                        unreachable!()
                    }
                },
            },
        }
        Ok(())
    })?;

    Ok(())
}
