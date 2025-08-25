pub mod icmpv4;
pub mod icmpv6;

use icmpv4::Icmpv4Packet;
use icmpv6::Icmpv6Packet;

#[derive(Debug, Copy, Clone)]
pub enum IcmpPacket {
    V4(Icmpv4Packet),
    V6(Icmpv6Packet),
}
