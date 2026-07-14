//! flow control and channel quality score.

use std::collections::VecDeque;

pub const SLOW_DOWN_BELOW: f64 = 0.85;
pub const SPEED_UP_ABOVE: f64 = 0.95;
pub const FPS_STEP: i32 = 5;
pub const CQS_WINDOW: usize = 100;
pub const FLOW_SIGNAL_INTERVAL: u32 = 30; // at most one signal per 30 records

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    SlowDown,
    SpeedUp,
}

/// Receiver side: record each frame attempt, read the current signal. At most
/// one SLOW_DOWN/SPEED_UP is emitted per FLOW_SIGNAL_INTERVAL record() calls -
/// per-frame signalling would oscillate the sender's fps.
pub struct FlowControl {
    window: usize,
    results: VecDeque<bool>,
    since_signal: u32, // record() calls since the last emitted signal
}

impl Default for FlowControl {
    /// Uses the default [`CQS_WINDOW`].
    fn default() -> Self {
        Self::new(CQS_WINDOW)
    }
}

impl FlowControl {
    pub fn new(window: usize) -> Self {
        Self {
            window,
            results: VecDeque::with_capacity(window),
            since_signal: 0,
        }
    }

    pub fn record(&mut self, decoded_ok: bool) {
        if self.results.len() == self.window {
            self.results.pop_front();
        }
        self.results.push_back(decoded_ok);
        self.since_signal += 1;
    }

    /// Rolling decode ratio, 1.0 when nothing attempted.
    pub fn cqs(&self) -> f64 {
        if self.results.is_empty() {
            return 1.0;
        }
        let ok = self.results.iter().filter(|&&r| r).count();
        ok as f64 / self.results.len() as f64
    }

    /// SLOW_DOWN, SPEED_UP, or None per the thresholds, rate-limited to one
    /// emission per FLOW_SIGNAL_INTERVAL record() calls. A suppressed signal is
    /// not emitted (None).
    pub fn signal(&mut self) -> Option<Signal> {
        if self.results.is_empty() {
            return None;
        }
        let cqs = self.cqs();
        let signal = if cqs < SLOW_DOWN_BELOW {
            Signal::SlowDown
        } else if cqs > SPEED_UP_ABOVE {
            Signal::SpeedUp
        } else {
            return None;
        };
        if self.since_signal < FLOW_SIGNAL_INTERVAL {
            return None;
        }
        self.since_signal = 0;
        Some(signal)
    }
}

/// Sender side: +/-5 fps per signal, within negotiated bounds.
pub fn adjust_fps(current: i32, signal: Option<Signal>, min_fps: i32, max_fps: i32) -> i32 {
    match signal {
        Some(Signal::SlowDown) => (current - FPS_STEP).max(min_fps),
        Some(Signal::SpeedUp) => (current + FPS_STEP).min(max_fps),
        None => current,
    }
}
