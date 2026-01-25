pub mod igmpv1;
pub mod igmpv2;
pub mod igmpv3;

use std::fmt::Display;

use ratatui::{Frame, layout::Rect};

use crate::packet::network::igmp::{
    igmpv1::IGMPv1Packet, igmpv2::IGMPv2Packet, igmpv3::IGMPv3Packet,
};

#[derive(Debug, Copy, Clone)]
pub enum IgmpPacket {
    V1(IGMPv1Packet),
    V2(IGMPv2Packet),
    V3(IGMPv3Packet),
}

impl IgmpPacket {
    pub fn render(self, block: Rect, frame: &mut Frame) {
        match self {
            IgmpPacket::V1(packet) => {
                packet.render(block, frame);
            }
            IgmpPacket::V2(packet) => {
                packet.render(block, frame);
            }
            IgmpPacket::V3(packet) => {
                packet.render(block, frame);
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IgmpType {
    MembershipQuery = 0x11,
    IGMPv1MembershipReport = 0x12,
    IGMPv2MembershipReport = 0x16,
    IGMPv3MembershipReport = 0x22,
    LeaveGroup = 0x17,
}

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

impl Display for IgmpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IgmpType::MembershipQuery => {
                write!(f, "Membership Query")
            }
            IgmpType::IGMPv1MembershipReport => {
                write!(f, "IGMPv1 Membership Report")
            }
            IgmpType::IGMPv2MembershipReport => {
                write!(f, "IGMPv2 Membership Report")
            }
            IgmpType::IGMPv3MembershipReport => {
                write!(f, "IGMPv3 Membership Report")
            }
            IgmpType::LeaveGroup => {
                write!(f, "Leave Group")
            }
        }
    }
}
