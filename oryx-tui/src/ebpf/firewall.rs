use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::{HashMap, MapData};
use oryx_common::MAX_RULES_PORT;

use crate::section::firewall::BlockedPort;

pub fn update_ipv4_blocklist(
    ipv4_firewall: &mut HashMap<MapData, u32, [u16; MAX_RULES_PORT]>,
    addr: Ipv4Addr,
    port: BlockedPort,
    to_insert: bool,
) {
    if let Ok(mut blocked_ports) = ipv4_firewall.get(&addr.to_bits(), 0) {
        match port {
            BlockedPort::Single(port) => {
                if to_insert {
                    if let Some((first_zero_index, _)) = blocked_ports
                        .iter()
                        .enumerate()
                        .find(|(_, &value)| value == 0)
                    {
                        blocked_ports[first_zero_index] = port;
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        unreachable!();
                    }
                } else {
                    let not_null_ports =
                        blocked_ports.into_iter().filter(|p| *p != 0 && *p != port);

                    let mut blocked_ports = [0; MAX_RULES_PORT];

                    for (idx, p) in not_null_ports.enumerate() {
                        blocked_ports[idx] = p;
                    }

                    if blocked_ports.iter().all(|&port| port == 0) {
                        ipv4_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv4_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if to_insert {
                    ipv4_firewall
                        .insert(addr.to_bits(), [0; MAX_RULES_PORT], 0)
                        .unwrap();
                } else {
                    ipv4_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if to_insert {
        let mut blocked_ports: [u16; MAX_RULES_PORT] = [0; MAX_RULES_PORT];
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

pub fn update_ipv6_blocklist(
    ipv6_firewall: &mut HashMap<MapData, u128, [u16; MAX_RULES_PORT]>,
    addr: Ipv6Addr,
    port: BlockedPort,
    to_insert: bool,
) {
    if let Ok(mut blocked_ports) = ipv6_firewall.get(&addr.to_bits(), 0) {
        match port {
            BlockedPort::Single(port) => {
                if to_insert {
                    if let Some((first_zero_index, _)) = blocked_ports
                        .iter()
                        .enumerate()
                        .find(|(_, &value)| value == 0)
                    {
                        blocked_ports[first_zero_index] = port;
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    } else {
                        unreachable!(); // list is full
                    }
                } else {
                    let not_null_ports =
                        blocked_ports.into_iter().filter(|p| *p != 0 && *p != port);

                    let mut blocked_ports = [0; MAX_RULES_PORT];

                    for (idx, p) in not_null_ports.enumerate() {
                        blocked_ports[idx] = p;
                    }

                    if blocked_ports.iter().all(|&port| port == 0) {
                        ipv6_firewall.remove(&addr.to_bits()).unwrap();
                    } else {
                        ipv6_firewall
                            .insert(addr.to_bits(), blocked_ports, 0)
                            .unwrap();
                    }
                }
            }
            BlockedPort::All => {
                if to_insert {
                    ipv6_firewall
                        .insert(addr.to_bits(), [0; MAX_RULES_PORT], 0)
                        .unwrap();
                } else {
                    ipv6_firewall.remove(&addr.to_bits()).unwrap();
                }
            }
        }
    } else if to_insert {
        let mut blocked_ports: [u16; MAX_RULES_PORT] = [0; MAX_RULES_PORT];
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
