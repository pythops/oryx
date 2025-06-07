use std::{
    fs::{create_dir, OpenOptions},
    io::prelude::*,
    os::unix::fs::chown,
};

use chrono::Local;

use crate::{
    app::AppResult,
    packet::{
        network::{IpPacket, IpProto},
        AppPacket, NetworkPacket,
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

    let headers = ("Src Ip", "Src Port", "Dst Ip", "Dst Port", "Protocol");
    writeln!(
        file,
        "{:39}  {:11}  {:39}  {:11}  {}\n",
        headers.0, headers.1, headers.2, headers.3, headers.4
    )?;
    for packet in packets {
        match packet.frame.payload {
            NetworkPacket::Arp(p) => {
                writeln!(
                    file,
                    "{:39}  {:^11}  {:39}  {:^11}  ARP",
                    p.src_mac.to_string(),
                    "-",
                    p.dst_mac.to_string(),
                    "-"
                )?;
            }
            NetworkPacket::Ip(packet) => match packet {
                IpPacket::V4(ipv4_packet) => match ipv4_packet.proto {
                    IpProto::Tcp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  TCP",
                            ipv4_packet.src_ip, p.src_port, ipv4_packet.dst_ip, p.dst_port
                        )?;
                    }
                    IpProto::Udp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  UDP",
                            ipv4_packet.src_ip, p.src_port, ipv4_packet.dst_ip, p.dst_port
                        )?;
                    }
                    IpProto::Icmp(_) => {
                        writeln!(
                            file,
                            "{:39}  {:^11}  {:39}  {:^11}  ICMP",
                            ipv4_packet.src_ip, "-", ipv4_packet.dst_ip, "-"
                        )?;
                    }
                },
                IpPacket::V6(ipv6_packet) => match ipv6_packet.proto {
                    IpProto::Tcp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  TCP",
                            ipv6_packet.src_ip, p.src_port, ipv6_packet.dst_ip, p.dst_port
                        )?;
                    }
                    IpProto::Udp(p) => {
                        writeln!(
                            file,
                            "{:39}  {:<11}  {:39}  {:<11}  UDP",
                            ipv6_packet.src_ip, p.src_port, ipv6_packet.dst_ip, p.dst_port
                        )?;
                    }
                    IpProto::Icmp(_) => {
                        writeln!(
                            file,
                            "{:39}  {:^11}  {:39}  {:^11}  ICMP",
                            ipv6_packet.src_ip, "-", ipv6_packet.dst_ip, "-"
                        )?;
                    }
                },
            },
        }
    }

    Ok(())
}
