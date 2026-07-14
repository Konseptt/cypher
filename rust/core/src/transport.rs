//! the transport boundary. The protocol core never touches display or camera
//! APIs directly; real screen/camera/BLE implementations live behind this
//! trait, and tests use the loopback pair.
//!
//! An unpaired transport has no back channel - that IS broadcast mode, so
//! [`LoopbackTransport`] returns [`NoBackChannel`] when unpaired.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use thiserror::Error;

/// No back channel available - the caller falls back to broadcast mode.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("no back channel available")]
pub struct NoBackChannel;

/// A frame requested from an empty capture queue / inbox.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct Empty(pub &'static str);

/// Fields a transport contributes to BEACON capability negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub width: u16,
    pub height: u16,
    pub max_fps: u8,
    pub cell_size: u8,
}

/// Default display/sensor capabilities.
pub const DEFAULT_CAPS: Capabilities = Capabilities {
    width: 1920,
    height: 1080,
    max_fps: 30,
    cell_size: 4,
};

/// The transport boundary. Sender methods render frames and report display
/// capabilities; receiver methods capture frames and report sensor
/// capabilities; the back-channel pair raises [`NoBackChannel`] when
/// unavailable.
pub trait Transport {
    // sender side
    fn render_frame(&mut self, wire: &[u8]);
    fn display_capabilities(&self) -> Capabilities;

    // receiver side
    /// # Errors
    /// [`Empty`] if no frame is waiting on screen.
    fn capture_frame(&mut self) -> Result<Vec<u8>, Empty>;
    fn sensor_capabilities(&self) -> Capabilities;

    // both sides; return `NoBackChannel` if unavailable.
    /// # Errors
    /// [`NoBackChannel`] if no back channel is available (broadcast mode).
    fn back_channel_send(&mut self, message: Vec<u8>) -> Result<(), NoBackChannel>;
    /// # Errors
    /// [`NoBackChannel`] if no back channel is available, or [`Empty`] wrapped
    /// as `Ok(None)` when the channel exists but no message is waiting.
    fn back_channel_recv(&mut self) -> Result<Vec<u8>, BackChannelRecvError>;
}

/// `back_channel_recv` distinguishes "no channel" (broadcast) from "channel
/// exists but empty".
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackChannelRecvError {
    #[error("no back channel available")]
    NoBackChannel,
    #[error("no message waiting")]
    Empty,
}

/// Shared FIFO queues behind an `Arc<Mutex<..>>` so a loopback pair can hand a
/// rendered frame to the peer's capture queue and a message to the peer's inbox.
// ponytail: one Mutex per queue, cloned Arcs; no lock-free tricks - a test
// transport is never a throughput path.
type Queue<T> = Arc<Mutex<VecDeque<T>>>;

/// In-memory transport for tests and the end-to-end loopback: rendered frames
/// appear on the peer's camera, back-channel messages in the peer's inbox.
/// Unpaired = broadcast mode (no back channel).
pub struct LoopbackTransport {
    caps: Capabilities,
    // When paired, `render_frame` pushes onto the PEER's screen and
    // `capture_frame` pops from OUR OWN. `back_channel_send` pushes onto the
    // peer's inbox; `back_channel_recv` pops from our own.
    my_screen: Queue<Vec<u8>>,
    my_inbox: Queue<Vec<u8>>,
    peer_screen: Option<Queue<Vec<u8>>>,
    peer_inbox: Option<Queue<Vec<u8>>>,
}

impl LoopbackTransport {
    pub fn new(capabilities: Capabilities) -> Self {
        Self {
            caps: capabilities,
            my_screen: Arc::new(Mutex::new(VecDeque::new())),
            my_inbox: Arc::new(Mutex::new(VecDeque::new())),
            peer_screen: None,
            peer_inbox: None,
        }
    }

    /// Test helper: return a clone of the screen queue Arc so test code
    /// can drain frames independently of any session borrowing this transport.
    // ponytail: Arc clone only - zero-copy, no synchronisation beyond the Mutex
    pub fn screen_arc(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        Arc::clone(&self.my_screen)
    }

    /// Test helper: return a clone of the inbox queue Arc so test code
    /// can drain back-channel messages independently of any session borrowing
    /// this transport.
    pub fn inbox_arc(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        Arc::clone(&self.my_inbox)
    }
}

impl Transport for LoopbackTransport {
    fn render_frame(&mut self, wire: &[u8]) {
        // Unpaired: land on our own screen.
        let screen = self.peer_screen.as_ref().unwrap_or(&self.my_screen);
        screen
            .lock()
            .expect("loopback lock")
            .push_back(wire.to_vec());
    }

    fn display_capabilities(&self) -> Capabilities {
        self.caps
    }

    fn capture_frame(&mut self) -> Result<Vec<u8>, Empty> {
        self.my_screen
            .lock()
            .expect("loopback lock")
            .pop_front()
            .ok_or(Empty("no frame on screen"))
    }

    fn sensor_capabilities(&self) -> Capabilities {
        self.caps
    }

    fn back_channel_send(&mut self, message: Vec<u8>) -> Result<(), NoBackChannel> {
        let inbox = self.peer_inbox.as_ref().ok_or(NoBackChannel)?;
        inbox.lock().expect("loopback lock").push_back(message);
        Ok(())
    }

    fn back_channel_recv(&mut self) -> Result<Vec<u8>, BackChannelRecvError> {
        if self.peer_inbox.is_none() {
            return Err(BackChannelRecvError::NoBackChannel);
        }
        self.my_inbox
            .lock()
            .expect("loopback lock")
            .pop_front()
            .ok_or(BackChannelRecvError::Empty)
    }
}

/// A paired loopback: `a` renders to `b`'s camera and vice versa, back-channel
/// messages cross to the peer's inbox.
pub fn loopback_pair(
    caps_a: Capabilities,
    caps_b: Capabilities,
) -> (LoopbackTransport, LoopbackTransport) {
    let mut a = LoopbackTransport::new(caps_a);
    let mut b = LoopbackTransport::new(caps_b);
    a.peer_screen = Some(Arc::clone(&b.my_screen));
    a.peer_inbox = Some(Arc::clone(&b.my_inbox));
    b.peer_screen = Some(Arc::clone(&a.my_screen));
    b.peer_inbox = Some(Arc::clone(&a.my_inbox));
    (a, b)
}
