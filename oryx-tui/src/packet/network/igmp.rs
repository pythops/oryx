pub mod igmpv1;
pub mod igmpv2;
pub mod igmpv3;

use crate::packet::network::igmp::igmpv1::IGMPv1Packet;

#[derive(Debug, Copy, Clone)]
pub enum IgmpPacket {
    V1(IGMPv1Packet),
    // V2(IGMPv2Packet),
    // V3(IGMPv3),
}

#[derive(Debug, Copy, Clone)]
pub enum IgmpType {
    MembershipQuery = 0x11,
    IGMPv1MembershipReport = 0x12,
    IGMPv2MembershipReport = 0x16,
    IGMPv3MembershipReport = 0x22,
    LeaveGroup = 0x17,
}

// impl From<u8> for IgmpType {
//     fn from(value: u8) -> Self {
//         match value {
//             0x11 => IgmpType::MembershipQuery,
//             0x12 => IgmpType::IGMPv1MembershipReport,
//             0x16 => IgmpType::IGMPv2MembershipReport,
//             0x22 => IgmpType::IGMPv3MembershipReport,
//             0x17 => IgmpType::LeaveGroup,
//             _ => unreachable!(),
//         }
//     }
// }

impl TryFrom<u8> for IgmpType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x11 => Ok(IgmpType::MembershipQuery),
            0x12 => Ok(IgmpType::IGMPv1MembershipReport),
            0x16 => Ok(IgmpType::IGMPv2MembershipReport),
            0x22 => Ok(IgmpType::IGMPv3MembershipReport),
            0x17 => Ok(IgmpType::LeaveGroup),
            _ => Err("Unknown igmp type"),
        }
    }
}
