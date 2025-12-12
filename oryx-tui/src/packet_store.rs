use crate::packet::AppPacket;
use anyhow::Result;
use branches::{likely, unlikely};
use cacheguard::CacheGuard;
use std::cell::RefCell;
use std::ops::{Deref, RangeBounds};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
// The double edged sword, Too high increases copy time and contention, Too low increases number of allocations
const BUFFER_SIZE: usize = 32 * 1024;

#[derive(Debug)]
pub struct PacketStoreInner {
    // It is here so user would know if archive that it read is changed while reading latest
    latest_token: CacheGuard<AtomicUsize>,
    // It is here so when new entry is geting added, user can spin over this instead of locking the RwLock
    archives_token: CacheGuard<AtomicUsize>,
    // Total number of packets stored
    length: CacheGuard<AtomicUsize>,
    // Recent packets stored here
    latest: RwLock<Vec<AppPacket>>,
    // Old packets stored here in chunks of BUFFER_SIZE
    archives: RwLock<Vec<Arc<Vec<AppPacket>>>>,
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
                latest_token: CacheGuard::new(AtomicUsize::new(0)),
                latest: RwLock::new(Vec::with_capacity(BUFFER_SIZE)),
                archives: RwLock::new(Vec::new()),
                archives_token: CacheGuard::new(AtomicUsize::new(0)),
                length: CacheGuard::new(AtomicUsize::new(0)),
            }),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.length.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        unlikely(self.len() == 0)
    }

    #[inline]
    pub fn discard_archive(&self, index: usize) {
        let mut archives = self.archives.write().unwrap();
        if likely(index < archives.len()) {
            archives[index] = Arc::new(Vec::new());
        }
    }

    #[inline]
    pub fn write(&self, packet: &AppPacket) {
        let mut latest = self.latest.write().unwrap();
        latest.push(*packet);
        if unlikely(latest.len() >= BUFFER_SIZE) {
            assert!(latest.len() == BUFFER_SIZE);
            let full_buffer = std::mem::replace(&mut *latest, Vec::with_capacity(BUFFER_SIZE));
            self.latest_token.fetch_add(1, Ordering::SeqCst);
            drop(latest);
            let mut archive = self.archives.write().unwrap();
            archive.push(Arc::new(full_buffer));
            self.archives_token.fetch_add(1, Ordering::SeqCst);
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
        while likely(i < packets.len()) {
            let mut latest = self.latest.write().unwrap();
            let remaining_capacity = BUFFER_SIZE - latest.len();
            let to_copy = remaining_capacity.min(packets.len() - i);
            latest.extend_from_slice(&packets[i..i + to_copy]);
            self.length.fetch_add(to_copy, Ordering::Relaxed);
            i += to_copy;
            if unlikely(latest.len() >= BUFFER_SIZE) {
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
        loop {
            let current_archive_length = self.archives_token.load(Ordering::SeqCst);
            let latest_token = self.latest_token.load(Ordering::SeqCst);

            if i >= self.len() {
                return None;
            }

            // Check if in archives
            if likely(i < current_archive_length * BUFFER_SIZE) {
                let archive_index = i / BUFFER_SIZE;
                let index_in_archive = i % BUFFER_SIZE;

                if let (Some(archive), _) = self.archive_at(archive_index) {
                    return Some(archive[index_in_archive]);
                }
                // Discarded archive or out of bounds
                return None;
            }

            // Check in latest
            let latest = self.latest.read().unwrap();
            if unlikely(latest_token != self.latest_token.load(Ordering::SeqCst)) {
                drop(latest);
                while self.archives_token.load(Ordering::Relaxed) == current_archive_length {
                    std::thread::yield_now();
                }
                continue; // Retry, archive was updated
            }

            let index_in_latest = i % BUFFER_SIZE;
            if index_in_latest < latest.len() {
                return Some(latest[index_in_latest]);
            }

            return None;
        }
    }

    #[inline]
    pub fn write_range_into<R>(&self, range: R, output: &mut Vec<AppPacket>)
    where
        R: RangeBounds<usize>,
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

        // reserve
        if end != usize::MAX {
            output.reserve(end - start);
        }

        loop {
            let current_archive_length = self.archives_token.load(Ordering::SeqCst);
            let latest_token = self.latest_token.load(Ordering::SeqCst);
            // Process archives
            while likely(i < current_archive_length * BUFFER_SIZE && i < end) {
                let archive_index = i / BUFFER_SIZE;
                let start_in_archive = i % BUFFER_SIZE;
                let remaining = (end - i).min(BUFFER_SIZE - start_in_archive);

                if let (Some(archive), _) = self.archive_at(archive_index) {
                    let end_in_archive = (start_in_archive + remaining).min(archive.len());
                    output.extend_from_slice(&archive[start_in_archive..end_in_archive]);
                    i += end_in_archive - start_in_archive;
                } else {
                    // Discarded archive, skip it
                    i += remaining;
                }
            }

            if i >= end {
                assert!(i == end);
                return;
            }

            let latest = self.latest.read().unwrap();
            if unlikely(latest_token != self.latest_token.load(Ordering::SeqCst)) {
                drop(latest);
                while self.archives_token.load(Ordering::Relaxed) == current_archive_length {
                    std::thread::yield_now();
                }
                continue; // Retry, archive was updated
            }

            if unlikely(latest.is_empty()) {
                return;
            }

            let start_in_latest = i % BUFFER_SIZE;
            let end_in_latest = (start_in_latest + (end - i)).min(latest.len());

            if start_in_latest >= latest.len() {
                return;
            }

            output.extend_from_slice(&latest[start_in_latest..end_in_latest]);
            return;
        }
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
            let current_archive_length = self.archives_token.load(Ordering::SeqCst);
            let latest_token = self.latest_token.load(Ordering::SeqCst);
            // Process archives
            while likely(i < current_archive_length * BUFFER_SIZE && i < end) {
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
            if unlikely(latest_token != self.latest_token.load(Ordering::SeqCst)) {
                drop(latest);
                while self.archives_token.load(Ordering::Relaxed) == current_archive_length {
                    std::thread::yield_now();
                }
                continue; // Retry, archive was updated
            }

            if unlikely(latest.is_empty()) {
                return Ok(i - start);
            }

            let start_in_latest = i % BUFFER_SIZE;
            let end_in_latest = (start_in_latest + (end - i)).min(latest.len());

            if start_in_latest >= latest.len() {
                return Ok(i - start);
            }

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
