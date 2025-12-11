use crate::packet::AppPacket;
use anyhow::Result;
use std::cell::RefCell;
use std::ops::{Deref, RangeBounds};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
// The double edged sword, Too high increases copy time and contention, Too low increases number of allocations
const BUFFER_SIZE: usize = 32 * 1024;

#[derive(Debug)]
pub struct PacketStoreInner {
    // Recent packets stored here
    latest: RwLock<Vec<AppPacket>>,
    // It is here so user would know if archive that it read is changed while reading latest
    latest_token: AtomicUsize,
    // Old packets stored here in chunks of BUFFER_SIZE
    archives: RwLock<Vec<Arc<Vec<AppPacket>>>>,
    // It is here so when new entry is geting added, user can spin over this instead of locking the RwLock
    archives_token: AtomicUsize,
    // Total number of packets stored
    length: AtomicUsize,
}

#[derive(Debug)]
pub struct PacketStore {
    inner: Arc<PacketStoreInner>,
}

impl Default for PacketStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PacketStore {
    type Target = PacketStoreInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Clone for PacketStore {
    fn clone(&self) -> Self {
        PacketStore {
            inner: Arc::clone(&self.inner),
        }
    }
}

thread_local! {
    // THREAD_LOCAL reused buffer to avoid heap allocations
    static THREAD_BUFFER: RefCell<Vec<AppPacket>> = RefCell::new(Vec::with_capacity(BUFFER_SIZE));
}

impl PacketStore {
    pub fn new() -> Self {
        PacketStore {
            inner: Arc::new(PacketStoreInner {
                latest_token: AtomicUsize::new(0),
                latest: RwLock::new(Vec::with_capacity(BUFFER_SIZE)),
                archives: RwLock::new(Vec::new()),
                archives_token: AtomicUsize::new(0),
                length: AtomicUsize::new(0),
            }),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.length.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn discard_archive(&self, index: usize) {
        let mut archives = self.archives.write().unwrap();
        if index < archives.len() {
            archives[index] = Arc::new(Vec::new());
        }
    }

    #[inline]
    pub fn write(&self, packet: &AppPacket) {
        let mut latest = self.latest.write().unwrap();
        latest.push(*packet);
        if latest.len() >= BUFFER_SIZE {
            assert!(latest.len() == BUFFER_SIZE);
            let latest_cloned = latest.clone();
            latest.clear();
            self.latest_token.fetch_add(1, Ordering::Release);
            drop(latest);
            let mut archive = self.archives.write().unwrap();
            archive.push(Arc::new(latest_cloned));
            self.archives_token.fetch_add(1, Ordering::Release);
        }
        self.length.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn archive_at(&self, index: usize) -> (Option<Arc<Vec<AppPacket>>>, usize) {
        let archive = self.archives.read().unwrap();
        (archive.get(index).cloned(), archive.len())
    }

    #[inline]
    pub fn write_many(&self, packets: &[AppPacket]) {
        let mut i = 0;
        while i < packets.len() {
            let mut latest = self.latest.write().unwrap();
            let remaining_capacity = BUFFER_SIZE - latest.len();
            let to_copy = remaining_capacity.min(packets.len() - i);
            latest.extend_from_slice(&packets[i..i + to_copy]);
            self.length.fetch_add(to_copy, Ordering::Relaxed);
            i += to_copy;
            if latest.len() >= BUFFER_SIZE {
                assert!(latest.len() == BUFFER_SIZE);
                let latest_cloned = latest.clone();
                latest.clear();
                self.latest_token.fetch_add(1, Ordering::Release);
                drop(latest);
                let mut archive = self.archives.write().unwrap();
                archive.push(Arc::new(latest_cloned));
                self.archives_token.fetch_add(1, Ordering::Release);
            }
        }
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<AppPacket> {
        let archive_index = i / BUFFER_SIZE;
        let index_in_archive = i % BUFFER_SIZE;
        let processed_archive_length = self.archives_token.load(Ordering::Acquire);
        if archive_index < processed_archive_length {
            let res = self.archive_at(archive_index);
            if let Some(res) = res.0 {
                return res.get(index_in_archive).cloned();
            }
        } else {
            let latest = self.latest.read().unwrap();
            if i < processed_archive_length * BUFFER_SIZE + latest.len() {
                return latest.get(index_in_archive).cloned();
            }
        }
        None
    }

    // only use for small ranges
    #[inline]
    pub fn clone_range<R>(&self, range: R) -> Vec<AppPacket>
    where
        R: RangeBounds<usize>,
    {
        let mut packets = Vec::with_capacity(match (&range.start_bound(), &range.end_bound()) {
            (std::ops::Bound::Included(s), std::ops::Bound::Included(e)) => *e - *s + 1,
            (std::ops::Bound::Included(s), std::ops::Bound::Excluded(e)) => *e - *s,
            (std::ops::Bound::Excluded(s), std::ops::Bound::Included(e)) => *e - *s,
            (std::ops::Bound::Excluded(s), std::ops::Bound::Excluded(e)) => *e - *s - 1,
            _ => 0,
        });
        self.for_each_range(range, |packet| {
            packets.push(*packet);
            Ok(())
        })
        .unwrap();
        packets
    }

    #[inline]
    pub fn for_each<F>(&self, f: F) -> Result<usize>
    where
        F: FnMut(&AppPacket) -> Result<()>,
    {
        self.for_each_range(0.., f)
    }

    // returns number of processed packets
    #[inline]
    pub fn for_each_range<R, F>(&self, range: R, mut f: F) -> Result<usize>
    where
        R: RangeBounds<usize>,
        F: FnMut(&AppPacket) -> Result<()>,
    {
        let start = match range.start_bound() {
            std::ops::Bound::Included(b) => *b,
            std::ops::Bound::Excluded(b) => *b + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let mut i = start;
        let end = match range.end_bound() {
            std::ops::Bound::Included(b) => *b + 1,
            std::ops::Bound::Excluded(b) => *b,
            std::ops::Bound::Unbounded => usize::MAX,
        };

        loop {
            let latest_token = self.latest_token.load(Ordering::Acquire);
            let current_archive_length = self.archives_token.load(Ordering::Acquire);
            // Process archives
            while i < current_archive_length * BUFFER_SIZE && i < end {
                let archive_index = i / BUFFER_SIZE;
                let start_in_archive = i % BUFFER_SIZE;
                let remaining = (end - i).min(BUFFER_SIZE - start_in_archive);

                if let (Some(archive), _) = self.archive_at(archive_index) {
                    let end_in_archive = (start_in_archive + remaining).min(archive.len());
                    for packet in &archive[start_in_archive..end_in_archive] {
                        f(packet)?;
                    }
                    i += end_in_archive - start_in_archive;
                } else {
                    // Discarded archive, skip it
                    i += remaining;
                }
            }

            if i >= end {
                assert!(i == end);
                return Ok(i - start);
            }

            let latest = self.latest.read().unwrap();
            if latest_token != self.latest_token.load(Ordering::Acquire) {
                drop(latest);
                continue; // Retry, archive was updated
            }

            let start_in_latest = i % BUFFER_SIZE;
            let end_in_latest = (start_in_latest + (end - i)).min(latest.len());

            THREAD_BUFFER.with(move |buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.extend_from_slice(&latest[start_in_latest..end_in_latest]);
                drop(latest);
                for packet in buffer.iter() {
                    f(packet)?;
                }
                buffer.clear();
                Ok::<(), anyhow::Error>(())
            })?;

            i += end_in_latest - start_in_latest;
            return Ok(i - start);
        }
    }
}
