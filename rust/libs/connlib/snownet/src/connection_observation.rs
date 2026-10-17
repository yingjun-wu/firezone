//! Bounded, metadata-only lifecycle observations. No sockets, credentials or packets.
use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStage {
    IceStarted,
    IceReady,
    HandshakeStarted,
    HandshakeCompleted,
    Ready,
    Failed,
    Closed,
    PathChanged,
    KeyRotated,
}
#[derive(Debug, Clone, Copy)]
pub struct ConnectionObservation<T> {
    pub connection: T,
    pub generation: u64,
    pub stage: ConnectionStage,
    pub elapsed: Duration,
}
#[derive(Debug)]
struct Attempt {
    generation: u64,
    start: Instant,
    seen: u16,
}
#[derive(Debug)]
pub(crate) struct ObservationLog<T> {
    next: u64,
    current: HashMap<T, Attempt>,
    pending: VecDeque<ConnectionObservation<T>>,
    dropped: u64,
}
impl<T> Default for ObservationLog<T> {
    fn default() -> Self {
        Self {
            next: 0,
            current: HashMap::new(),
            pending: VecDeque::new(),
            dropped: 0,
        }
    }
}
impl<T: Copy + Eq + Hash> ObservationLog<T> {
    pub fn begin(&mut self, id: T, ice: bool, now: Instant) {
        let before = self.pending.len();
        self.pending.retain(|event| event.connection != id);
        self.dropped = self
            .dropped
            .saturating_add((before - self.pending.len()) as u64);
        self.next = self.next.saturating_add(1);
        self.current.insert(
            id,
            Attempt {
                generation: self.next,
                start: now,
                seen: 0,
            },
        );
        if ice {
            self.record(id, ConnectionStage::IceStarted, now);
        }
    }
    pub fn record(&mut self, id: T, stage: ConnectionStage, now: Instant) {
        let Some(attempt) = self.current.get_mut(&id) else {
            return;
        };
        let repeat = matches!(
            stage,
            ConnectionStage::PathChanged | ConnectionStage::KeyRotated
        );
        let bit = 1u16 << (stage as u8);
        if !repeat && attempt.seen & bit != 0 {
            return;
        }
        attempt.seen |= bit;
        if self.pending.len() >= 256 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.pending.push_back(ConnectionObservation {
            connection: id,
            generation: attempt.generation,
            stage,
            elapsed: now.saturating_duration_since(attempt.start),
        });
    }
    pub fn terminal(&mut self, id: T, stage: ConnectionStage, now: Instant) {
        self.record(id, stage, now);
        self.current.remove(&id);
    }
    pub fn poll(&mut self) -> Option<ConnectionObservation<T>> {
        self.pending.pop_front()
    }
    pub fn lost(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
    }
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stages_are_once_per_generation_and_terminal_cannot_be_replayed() {
        let mut l = ObservationLog::default();
        let now = Instant::now();
        l.begin(1, true, now);
        l.record(1, ConnectionStage::Ready, now);
        l.record(1, ConnectionStage::Ready, now);
        l.terminal(1, ConnectionStage::Closed, now);
        l.record(1, ConnectionStage::Ready, now);
        let events = std::iter::from_fn(|| l.poll()).collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        l.begin(1, true, now);
        assert_ne!(events[0].generation, l.poll().unwrap().generation);
    }
    #[test]
    fn iceless_does_not_claim_ice_and_queue_is_bounded() {
        let mut l = ObservationLog::default();
        let now = Instant::now();
        l.begin(1, false, now);
        assert!(l.poll().is_none());
        for id in 0..400 {
            l.begin(id, true, now)
        }
        assert_eq!(std::iter::from_fn(|| l.poll()).count(), 256);
        assert_eq!(l.dropped(), 144);
    }
    #[test]
    fn path_and_rekey_events_repeat_without_creating_attempts() {
        let mut l = ObservationLog::default();
        let now = Instant::now();
        l.begin(1, false, now);
        for _ in 0..2 {
            l.record(1, ConnectionStage::PathChanged, now);
            l.record(1, ConnectionStage::KeyRotated, now);
        }
        let events = std::iter::from_fn(|| l.poll()).collect::<Vec<_>>();
        assert_eq!(events.len(), 4);
        assert!(
            events
                .iter()
                .all(|event| event.generation == events[0].generation)
        );
    }
}
