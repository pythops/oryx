use std::fs::{create_dir, OpenOptions};
use std::io::prelude::*;
use std::os::unix::fs::chown;

use oryx_common::IpPacket;

use crate::app::AppResult;

pub fn export(packets: &[IpPacket]) -> AppResult<()> {
    let uid = unsafe { libc::geteuid() };

    let oryx_export_dir = dirs::home_dir().unwrap().join("oryx");

    if !oryx_export_dir.exists() {
        create_dir(&oryx_export_dir)?;
        chown(&oryx_export_dir, Some(uid), Some(uid))?;
    }

    let oryx_export_file = oryx_export_dir.join("capture");

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
        match packet {
            IpPacket::Tcp(p) => {
                writeln!(
                    file,
                    "{:39}  {:<11}  {:39}  {:<11}  TCP",
                    p.src_ip, p.src_port, p.dst_ip, p.dst_port
                )?;
            }
            IpPacket::Udp(p) => {
                writeln!(
                    file,
                    "{:39}  {:<11}  {:39}  {:<11}  UDP",
                    p.src_ip, p.src_port, p.dst_ip, p.dst_port
                )?;
            }
            IpPacket::Icmp(p) => {
                writeln!(
                    file,
                    "{:39}  {:^11}  {:39}  {:^11}  ICMP",
                    p.src_ip, "-", p.dst_ip, "-"
                )?;
            }
        }
    }

    Ok(())
}
