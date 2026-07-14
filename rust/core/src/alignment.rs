//! receiver alignment: AQS computation and the alignment state machine.
//!
//! Sans-IO: one [`AlignmentMonitor::observe`] call per camera frame returns a
//! list of back-channel signals as `(msg_type, payload)` pairs. Signing and
//! sending are the caller's job - this module touches neither crypto nor
//! transport, uses an injected clock, and starts no threads.

use std::collections::VecDeque;

use thiserror::Error;

use crate::messages;

pub const ALIGNED: &str = "ALIGNED";
pub const DEGRADED: &str = "DEGRADED";
pub const LOST: &str = "LOST";
pub const RECOVERING: &str = "RECOVERING";

pub const ALIGNED_ABOVE: f32 = 0.75;
pub const LOST_BELOW: f32 = 0.5;
pub const LOST_CONSECUTIVE: u32 = 5;
pub const DECODE_WINDOW: usize = 30;
pub const ALIGNMENT_CADENCE: u64 = 10;

/// Invalid AQS input. `sharpness` crosses the trust boundary from the capture
/// layer, so [`aqs`] validates loudly.
#[derive(Debug, Error, PartialEq)]
pub enum AlignmentError {
    #[error("markers_found must be 0..4, got {0}")]
    Markers(u8),
    #[error("sharpness must be 0.0..1.0, got {0}")]
    Sharpness(f32),
    #[error("decode_ratio must be 0.0..1.0, got {0}")]
    DecodeRatio(f32),
    #[error("decoded_ok=true requires frame_number")]
    DecodedOkNeedsFrame,
}

/// Alignment Quality Score.
///
/// # Errors
/// [`AlignmentError`] if any input is out of range (validates loudly; sharpness
/// crosses the capture-layer trust boundary).
pub fn aqs(markers_found: u8, sharpness: f32, decode_ratio: f32) -> Result<f32, AlignmentError> {
    if markers_found > 4 {
        return Err(AlignmentError::Markers(markers_found));
    }
    if !(0.0..=1.0).contains(&sharpness) {
        return Err(AlignmentError::Sharpness(sharpness));
    }
    if !(0.0..=1.0).contains(&decode_ratio) {
        return Err(AlignmentError::DecodeRatio(decode_ratio));
    }
    Ok(markers_found as f32 / 4.0 * 0.5 + sharpness * 0.3 + decode_ratio * 0.2)
}

/// One back-channel signal: `(message_type, payload)`. Signing/sending is the
/// caller's job.
pub type Signal = (u8, Vec<u8>);

/// Receiver state machine. RESUMED is transient: the machine emits its RESUMED
/// signal and transitions straight to ALIGNED, so `.state` is never RESUMED.
pub struct AlignmentMonitor {
    clock: Box<dyn FnMut() -> f64 + Send>,
    cadence: u64,
    pub state: &'static str,
    pub last_decoded_frame: u64,
    pub lost_since: Option<f64>,
    window: VecDeque<bool>,
    lost_counter: u32,
    calls: u64,
}

impl AlignmentMonitor {
    /// No defined initial state; the receiver just decoded a BEACON, so it is
    /// aligned by construction.
    pub fn new(clock: Box<dyn FnMut() -> f64 + Send>, cadence: u64) -> Self {
        Self {
            clock,
            cadence,
            state: ALIGNED,
            last_decoded_frame: 0,
            lost_since: None,
            window: VecDeque::with_capacity(DECODE_WINDOW),
            lost_counter: 0,
            calls: 0,
        }
    }

    /// One camera frame. `decoded_ok` is tri-state: `None` leaves the decode
    /// window untouched, `Some(true)` requires `frame_number`.
    ///
    /// # Errors
    /// [`AlignmentError::DecodedOkNeedsFrame`] when `decoded_ok == Some(true)`
    /// without a `frame_number`; propagates [`aqs`] validation errors.
    pub fn observe(
        &mut self,
        markers_found: u8,
        sharpness: f32,
        decoded_ok: Option<bool>,
        frame_number: Option<u64>,
        is_keyframe: bool,
    ) -> Result<Vec<Signal>, AlignmentError> {
        self.calls += 1;

        if decoded_ok == Some(true) && frame_number.is_none() {
            return Err(AlignmentError::DecodedOkNeedsFrame);
        }
        if let Some(ok) = decoded_ok {
            if self.window.len() == DECODE_WINDOW {
                self.window.pop_front();
            }
            self.window.push_back(ok);
            if ok {
                self.last_decoded_frame = frame_number.expect("checked above");
            }
        }

        // Optimistic 1.0 on an empty window matches starting in ALIGNED.
        let decode_ratio = if self.window.is_empty() {
            1.0
        } else {
            self.window.iter().filter(|&&b| b).count() as f32 / self.window.len() as f32
        };
        let score = aqs(markers_found, sharpness, decode_ratio)?;

        let mut signals = Vec::new();
        match self.state {
            ALIGNED | DEGRADED => self.observe_stable(score, &mut signals),
            LOST => self.observe_lost(markers_found, score, &mut signals),
            RECOVERING => self.observe_recovering(
                markers_found,
                decoded_ok,
                frame_number,
                is_keyframe,
                &mut signals,
            ),
            _ => unreachable!("state is one of the four constants"),
        }

        // ALIGNMENT scores in ALIGNED, DEGRADED, RECOVERING. LOST does not emit
        // them.
        if self.calls.is_multiple_of(self.cadence)
            && matches!(self.state, ALIGNED | DEGRADED | RECOVERING)
        {
            signals.push((
                messages::ALIGNMENT,
                messages::pack_alignment(score, self.last_decoded_frame),
            ));
        }
        Ok(signals)
    }

    fn observe_stable(&mut self, score: f32, signals: &mut Vec<Signal>) {
        if score < LOST_BELOW {
            self.lost_counter += 1;
            if self.lost_counter >= LOST_CONSECUTIVE {
                self.enter_lost(signals);
            }
            return; // state otherwise unchanged while counting
        }
        self.lost_counter = 0;
        if score > ALIGNED_ABOVE {
            self.state = ALIGNED;
        } else if self.state != DEGRADED {
            // emit only on transition into DEGRADED
            self.state = DEGRADED;
            signals.push((messages::DEGRADED, messages::pack_degraded(score)));
        }
    }

    fn observe_lost(&mut self, markers_found: u8, score: f32, signals: &mut Vec<Signal>) {
        // Exit to RECOVERING on any corner markers detected.
        if markers_found >= 1 {
            self.state = RECOVERING;
            signals.push((
                messages::RESUME,
                messages::pack_resume(self.last_decoded_frame + 1, score),
            ));
        }
    }

    fn observe_recovering(
        &mut self,
        markers_found: u8,
        decoded_ok: Option<bool>,
        frame_number: Option<u64>,
        is_keyframe: bool,
        signals: &mut Vec<Signal>,
    ) {
        if is_keyframe && decoded_ok == Some(true) {
            signals.push((
                messages::RESUMED,
                messages::pack_resumed(frame_number.expect("keyframe decode carries a frame")),
            ));
            self.state = ALIGNED; // RESUMED is transient
        } else if markers_found == 0 {
            // A literal "AQS drops below 0.5" exit is contradictory (RECOVERING
            // is entered with AQS already below 0.5), so markers-vanish is the
            // symmetric counterpart of the markers-detected entry condition.
            self.enter_lost(signals);
        }
    }

    fn enter_lost(&mut self, signals: &mut Vec<Signal>) {
        self.state = LOST;
        signals.push((
            messages::PAUSE,
            messages::pack_pause(self.last_decoded_frame),
        ));
        self.lost_since = Some((self.clock)()); // reset alignment_timeout
        self.lost_counter = 0;
    }
}
