use clap::{
    Command, arg,
    builder::ValueParser,
    crate_description, crate_version,
    error::{ContextValue, ErrorKind},
};

use crate::interface::NetworkInterface;

fn parse_interface(interface: &str) -> Result<String, clap::Error> {
    let interfaces = NetworkInterface::list()
        .iter()
        .map(|interface| interface.name.clone())
        .collect::<Vec<String>>();

    if interfaces.contains(&interface.to_string()) {
        Ok(interface.to_string())
    } else {
        let mut err = clap::Error::new(ErrorKind::ValueValidation);
        err.insert(
            clap::error::ContextKind::ValidValue,
            ContextValue::Strings(interfaces),
        );
        Err(err)
    }
}

pub fn cli() -> Command {
    Command::new("oryx")
        .about(crate_description!())
        .version(crate_version!())
        .arg(
            arg!(--interface <interface>)
                .short('i')
                .help("Network interface")
                .required(false)
                .value_parser(ValueParser::new(parse_interface)),
        )
        .arg(
            arg!(--transport <transport>)
                .short('t')
                .help("Transport layer protocols")
                .required(false)
                .value_delimiter(',')
                .num_args(1..)
                .default_value("all")
                .value_parser(["tcp", "udp", "sctp", "all"]),
        )
        .arg(
            arg!(--network <network>)
                .help("Network layer protocols")
                .short('n')
                .required(false)
                .value_delimiter(',')
                .num_args(1..)
                .default_value("all")
                .value_parser(["ipv4", "ipv6", "icmpv4", "icmpv6", "igmp", "all"]),
        )
        .arg(
            arg!(--link <link>)
                .help("Network layer protocols")
                .short('l')
                .required(false)
                .value_delimiter(',')
                .num_args(1..)
                .default_value("all")
                .value_parser(["arp", "all"]),
        )
        .arg(
            arg!(--direction <direction>)
                .help("Traffic direction")
                .short('d')
                .required(false)
                .value_delimiter(',')
                .num_args(1..)
                .default_value("all")
                .value_parser(["ingress", "egress", "all"]),
        )
}
