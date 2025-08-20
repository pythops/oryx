use std::{
    fs::{OpenOptions, create_dir},
    io::prelude::*,
    os::unix::fs::chown,
};

use chrono::Local;

use crate::{
    app::AppResult,
    packet::{
        AppPacket, NetworkPacket,
        network::{IpPacket, IpProto},
    },
};

pub fn export(packets: &[AppPacket]) -> AppResult<()> {
    let uid = unsafe { libc::geteuid() };

    let local_date = Local::now().format("%Y-%m-%d_%H-%M");

    let oryx_export_dir = dirs::home_dir().unwrap().join("oryx");

    if !oryx_export_dir.exists() {
        create_dir(&oryx_export_dir)?;
        chown(&oryx_export_dir, Some(uid), Some(uid))?;
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
    for app_packet in packets {
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
                            ipv4_packet.src_ip, "-", ipv4_packet.dst_ip, "-", "ICMP", pid, date
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
                            ipv6_packet.src_ip, "-", ipv6_packet.dst_ip, "-", "ICMP", pid, date
                        )?;
                    }
                },
            },
        }
    }

    Ok(())
}
