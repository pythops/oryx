use core::fmt::Display;

#[derive(Debug, Copy, Clone)]
pub struct ArpPacket {
    pub arp_type: ArpType,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {} ARP", self.src_mac, self.dst_mac)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ArpType {
    Request,
    Reply,
}

impl Display for ArpType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Request => write!(f, "Arp Request"),
            Self::Reply => write!(f, "Arp Reply"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MacAddr(pub [u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        //FIX: workaround for the moment
        if self.0.iter().all(|x| *x == 0) {
            write!(f, "ff:ff:ff:ff:ff:ff",)
        } else {
            write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0].to_be(),
                self.0[1].to_be(),
                self.0[2].to_be(),
                self.0[3].to_be(),
                self.0[4].to_be(),
                self.0[5].to_be()
            )
        }
    }
}
