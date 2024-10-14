pub mod egress;
mod firewall;
pub mod ingress;

use std::{io, os::fd::AsRawFd};

use aya::{
    maps::{ring_buf::RingBufItem, MapData, RingBuf},
    Ebpf,
};

use mio::{event::Source, unix::SourceFd, Interest, Registry, Token};

pub struct RingBuffer<'a> {
    pub buffer: RingBuf<&'a mut MapData>,
}

impl<'a> RingBuffer<'a> {
    fn new(ebpf: &'a mut Ebpf) -> Self {
        let buffer = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        Self { buffer }
    }

    fn next(&mut self) -> Option<RingBufItem<'_>> {
        self.buffer.next()
    }
}

impl Source for RingBuffer<'_> {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).deregister(registry)
    }
}
enum EbpfTrafficDirection {
    Ingress = -1,
    Egress = 1,
}
