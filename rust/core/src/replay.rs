//! SESSION_ID replay cache.
//! Receiver-side primary replay defence: seen IDs are added after
//! SESSION_COMPLETE; any frame whose SESSION_ID is already cached is discarded
//! silently.

use std::collections::{HashMap, VecDeque};

pub const MAX_ENTRIES: usize = 1_000_000; // = 8 MB of ids
pub const DEFAULT_TTL: f64 = 24.0 * 3600.0;

/// Replay cache keyed by SESSION_ID. The clock is injectable so tests can drive
/// TTL expiry deterministically; production passes a monotonic clock. `order`
/// tracks insertion/recency (front = oldest) for LRU eviction and TTL pruning.
pub struct ReplayCache {
    ttl: f64,
    max_entries: usize,
    clock: Box<dyn FnMut() -> f64 + Send>,
    seen: HashMap<u64, f64>, // session_id -> expiry
    order: VecDeque<u64>,    // recency order, front = least-recently-added
}

impl ReplayCache {
    pub fn new(ttl: f64, max_entries: usize, clock: Box<dyn FnMut() -> f64 + Send>) -> Self {
        Self {
            ttl,
            max_entries,
            clock,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Record a seen SESSION_ID. Expired entries are pruned first, then the id
    /// is inserted (or refreshed to most-recent), evicting the oldest when the
    /// cache is full - LRU eviction.
    pub fn add(&mut self, session_id: u64) {
        let now = (self.clock)();
        self.prune_expired(now);
        if self.seen.contains_key(&session_id) {
            self.touch(session_id);
        } else if self.seen.len() >= self.max_entries {
            self.pop_oldest();
        }
        if self.seen.insert(session_id, now + self.ttl).is_none() {
            self.order.push_back(session_id);
        }
    }

    /// True if `session_id` is cached and unexpired. An expired entry is evicted
    /// on probe.
    pub fn contains(&mut self, session_id: u64) -> bool {
        match self.seen.get(&session_id).copied() {
            None => false,
            Some(expiry) => {
                if expiry <= (self.clock)() {
                    self.remove(session_id);
                    false
                } else {
                    true
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn prune_expired(&mut self, now: f64) {
        while let Some(&front) = self.order.front() {
            // Front is the oldest-added; its expiry is the earliest, so once it
            // survives, all later entries do too (all share the same ttl).
            match self.seen.get(&front) {
                Some(&expiry) if expiry <= now => {
                    self.order.pop_front();
                    self.seen.remove(&front);
                }
                _ => break,
            }
        }
    }

    fn pop_oldest(&mut self) {
        if let Some(oldest) = self.order.pop_front() {
            self.seen.remove(&oldest);
        }
    }

    fn touch(&mut self, session_id: u64) {
        if let Some(pos) = self.order.iter().position(|&id| id == session_id) {
            self.order.remove(pos);
            self.order.push_back(session_id);
        }
    }

    fn remove(&mut self, session_id: u64) {
        self.seen.remove(&session_id);
        if let Some(pos) = self.order.iter().position(|&id| id == session_id) {
            self.order.remove(pos);
        }
    }
}
