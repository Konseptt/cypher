//! Cypher CLI: The entry point for the optical file transmitter/receiver command line app.
//! Send subcommand converts a file to QR frames and wraps them in an MP4.
//! Receive subcommand reads an MP4 or takes webcam feed and spits the file back out.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use image::{Rgb, RgbImage};

use cypher::compression::LEVEL_SPEED;
use cypher::fountain::DEFAULT_OVERHEAD;
use cypher::session::{
    overhead_for_max_loss, symbol_size_for_max_wire, BroadcastReceiver, BroadcastSender,
    BROADCAST_SYMBOL_SIZE,
};
use cypher::transport::{Capabilities, Empty, LoopbackTransport, Transport};
use cypher::video::{camera_frames, read_frames, Mp4Writer};
use cypher::{crypto, phrase, qr};

/// Public password used for open channels that anyone can listen to.
const PUBLIC_PHRASE: &str = "cypher-public-broadcast";

#[derive(Parser)]
#[command(name = "cypher", about = "Cypher optical transfer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file as a Cypher broadcast video.
    Send(SendArgs),
    /// Receive a Cypher broadcast file.
    Receive(ReceiveArgs),
}

#[derive(Parser)]
struct ReceiveArgs {
    /// MP4 file to parse (offline mode).
    #[arg(long)]
    video: Option<PathBuf>,
    /// webcam mode (the default).
    #[arg(long)]
    camera: bool,
    /// Code word/phrase. Omit to be prompted.
    #[arg(long)]
    phrase: Option<String>,
    /// listen to a public broadcast.
    #[arg(long, conflicts_with = "phrase")]
    public: bool,
    /// Directory where the received file gets saved.
    #[arg(long, default_value = ".")]
    out: PathBuf,
    /// webcam device ID (0, 1) or path to video.
    #[arg(long, default_value = "0")]
    source: String,
    /// Quit if no QRs are decoded in this many seconds (default: wait forever).
    #[arg(long, visible_alias = "ttl")]
    timeout: Option<f64>,
}

#[derive(Parser)]
struct SendArgs {
    /// File path to send.
    path: PathBuf,
    /// Secret password (otherwise we make one for you).
    #[arg(long)]
    phrase: Option<String>,
    /// No password mode. Anyone can decrypt this.
    #[arg(long, conflicts_with = "phrase")]
    public: bool,
    /// Output MP4 path.
    #[arg(long, default_value = "transfer.mp4")]
    out: PathBuf,
    /// Show the video loop in a window instead of writing to disk.
    #[arg(long, conflicts_with = "out")]
    live: bool,
    /// frame rate.
    #[arg(long, default_value_t = 10)]
    fps: u32,
    /// Tiled grid size (e.g. 1, 2, or 3).
    #[arg(long, default_value_t = 1)]
    tiles: usize,
    /// receiver device target: phone|laptop|monitor or max bytes limit.
    #[arg(long)]
    display: Option<String>,
    /// Tolerable loss percentage (fountain repair overhead multiplier).
    #[arg(long)]
    max_loss: Option<i64>,
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is set before UNIX epoch?")
        .as_secs_f64()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Send(args) => send(args),
        Command::Receive(args) => receive(args),
    }
}

fn send(args: SendArgs) -> Result<()> {
    if !(1..=3).contains(&args.tiles) {
        bail!("--tiles must be 1, 2, or 3");
    }
    let extra_overhead = match args.max_loss {
        Some(loss) => {
            if !(0..=75).contains(&loss) {
                bail!("--max-loss must be 0..75 (percent of frames)");
            }
            Some(overhead_for_max_loss(loss as u32)?)
        }
        None => None,
    };

    // Grab display target preset or byte cap
    let packet_byte_cap = match args.display.as_deref() {
        None => None,
        Some(d) => Some(match d.to_lowercase().as_str() {
            "phone" => 250,
            "laptop" => 1000,
            "monitor" => 2000,
            _ => {
                let n: i64 = d.parse().map_err(|_| {
                    anyhow::anyhow!("--display must be phone|laptop|monitor or a number, got '{d}'")
                })?;
                if !(100..=2300).contains(&n) {
                    bail!("--display byte value must be 100..2300 (QR max capacity)");
                }
                n
            }
        }),
    };

    let file_data = std::fs::read(&args.path)
        .with_context(|| format!("could not read {}", args.path.display()))?;
    let file_name = args
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Setup password phrase
    let secret_phrase = if args.public {
        PUBLIC_PHRASE.to_string()
    } else {
        match &args.phrase {
            Some(p) => p.clone(),
            None => phrase::generate(phrase::DEFAULT_WORDS),
        }
    };
    if args.phrase.is_some() {
        let phrase_word_count = crypto::phrase_tokens(&secret_phrase).len();
        if phrase_word_count < 4 {
            eprintln!(
                "warning: '{secret_phrase}' is only {phrase_word_count} word(s) - pretty easy to hack; 4+ words recommended"
            );
        }
    }

    println!("file:         {file_name} ({} B)", file_data.len());
    if args.public {
        println!("PUBLIC broadcast - no password; anyone who records this screen can decrypt it");
    } else {
        println!("code phrase:  {secret_phrase}");
        println!("  (tell the receiver this password - without it, the video is just noise)");
    }

    let secret_key = crypto::key_from_phrase(&secret_phrase)?;
    let tile_info_text = if args.tiles > 1 {
        format!(" ({0}x{0} tiles/frame)", args.tiles)
    } else {
        String::new()
    };
    let help_text = if args.public {
        "--public".to_string()
    } else {
        format!("--phrase '{secret_phrase}'")
    };

    if args.live {
        let all_qr_frames = build_broadcast_frames(
            *secret_key.as_bytes(),
            &file_data,
            &file_name,
            args.tiles,
            packet_byte_cap,
            extra_overhead,
        )?;
        println!(
            "live:         looping {} frames{tile_info_text} @ {} fps in window (ESC/q to quit)",
            all_qr_frames.len(),
            args.fps
        );
        println!("receive:      cypher receive {help_text}");
        stream_live(&all_qr_frames, args.fps)?;
        return Ok(());
    }

    let all_qr_frames = render_broadcast(
        *secret_key.as_bytes(),
        &file_data,
        &args.out,
        &file_name,
        args.fps,
        args.tiles,
        packet_byte_cap,
        extra_overhead,
    )?;
    let duration_seconds = all_qr_frames as f64 / args.fps as f64;
    println!(
        "broadcast:    {all_qr_frames} frames{tile_info_text} -> {duration_seconds:.1}s video @ {} fps -> {}",
        args.fps,
        args.out.display()
    );
    println!(
        "receive:      cypher receive --video {} {help_text}",
        args.out.display()
    );
    Ok(())
}

/// Sanitize filename so sender can't drop a file in ../../../evil_place/
fn safe_dest(output_directory: &Path, incoming_name: &str) -> PathBuf {
    let file_basename = Path::new(incoming_name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let clean_name = if file_basename.is_empty() || file_basename == "." || file_basename == ".." {
        "received.bin".to_string()
    } else {
        file_basename
    };
    output_directory.join(clean_name)
}

/// Grab the secret key. If not passed on command line, prompt user in terminal.
fn phrase_to_psk(passed_phrase: Option<&str>) -> Result<[u8; 32]> {
    let phrase_to_use = match passed_phrase {
        Some(p) => p.to_string(),
        None => {
            eprint!("enter code phrase (leave blank for a public broadcast): ");
            let _ = std::io::stderr().flush();
            let mut user_input_line = String::new();
            let bytes_read = std::io::stdin()
                .lock()
                .read_line(&mut user_input_line)
                .context("reading code phrase")?;
            if bytes_read == 0 {
                bail!("no input - pass --phrase or --public");
            }
            let trimmed_phrase = user_input_line.trim_end_matches(['\r', '\n']).to_string();
            if trimmed_phrase.is_empty() {
                return Ok(*crypto::key_from_phrase(PUBLIC_PHRASE)?.as_bytes());
            }
            trimmed_phrase
        }
    };
    let word_count = crypto::phrase_tokens(&phrase_to_use).len();
    if word_count < 4 {
        eprintln!(
            "warning: phrase has only {word_count} word(s) - pretty weak; 4+ words recommended"
        );
    }
    Ok(*crypto::key_from_phrase(&phrase_to_use)?.as_bytes())
}

fn receive(args: ReceiveArgs) -> Result<()> {
    let secret_key = if args.public {
        *crypto::key_from_phrase(PUBLIC_PHRASE)?.as_bytes()
    } else {
        phrase_to_psk(args.phrase.as_deref())?
    };
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("could not create --out dir {}", args.out.display()))?;

    match &args.video {
        Some(video_file_path) => receive_video(video_file_path, secret_key, &args.out),
        None => receive_camera(&args, secret_key),
    }
}

/// Read through the video frames one by one and assemble the output file.
fn receive_video(video_file_path: &Path, secret_key: [u8; 32], output_directory: &Path) -> Result<()> {
    let mut receiver_guy = BroadcastReceiver::new(secret_key, None, "sender", true, None, Box::new(now_secs));
    let mut processed_frames: usize = 0;
    
    for current_frame in read_frames(video_file_path).with_context(|| format!("opening {}", video_file_path.display()))? {
        processed_frames += 1;
        receiver_guy
            .on_codes(qr::decode_all(&current_frame))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if receiver_guy.complete {
            break;
        }
    }

    if !receiver_guy.complete {
        if processed_frames > 0 && receiver_guy.packets_seen() == 0 {
            bail!(
                "wrong code phrase - read {processed_frames} frames but couldn't decrypt. double check the phrase"
            );
        }
        bail!(
            "video ended too early: still need more frames (only got {} packets after {processed_frames} frames)",
            receiver_guy.packets_seen()
        );
    }

    let payload_bytes = receiver_guy.data()?;
    let transfer_filename = if receiver_guy.transfer_name.is_empty() {
        "received.bin"
    } else {
        &receiver_guy.transfer_name
    };
    let destination_file = safe_dest(output_directory, transfer_filename);
    std::fs::write(&destination_file, &payload_bytes).with_context(|| format!("writing {}", destination_file.display()))?;
    
    let basename_string = destination_file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    println!(
        "received {basename_string} ({} B) from {processed_frames} frames -> {}",
        payload_bytes.len(),
        destination_file.display()
    );
    Ok(())
}

/// Helper harness that tracks how many frames we've written to output.
struct CaptureTransport {
    inner_transport: LoopbackTransport,
    rendered_count: usize,
    should_show: bool,
    estimated_total: usize,
}

impl Transport for CaptureTransport {
    fn render_frame(&mut self, wire: &[u8]) {
        self.rendered_count += 1;
        if self.should_show && self.rendered_count.is_multiple_of(100) {
            let percentage = std::cmp::min(99, 100 * self.rendered_count / self.estimated_total);
            eprint!(
                "\r  QR-encoding packets: {}/~{} ({percentage}%)",
                self.rendered_count, self.estimated_total
            );
            let _ = std::io::stderr().flush();
        }
        self.inner_transport.render_frame(wire);
    }
    fn display_capabilities(&self) -> Capabilities {
        self.inner_transport.display_capabilities()
    }
    fn capture_frame(&mut self) -> std::result::Result<Vec<u8>, Empty> {
        self.inner_transport.capture_frame()
    }
    fn sensor_capabilities(&self) -> Capabilities {
        self.inner_transport.sensor_capabilities()
    }
    fn back_channel_send(
        &mut self,
        message: Vec<u8>,
    ) -> std::result::Result<(), cypher::transport::NoBackChannel> {
        self.inner_transport.back_channel_send(message)
    }
    fn back_channel_recv(
        &mut self,
    ) -> std::result::Result<Vec<u8>, cypher::transport::BackChannelRecvError> {
        self.inner_transport.back_channel_recv()
    }
}

/// Convert input data payload into raw QR image frames.
fn build_broadcast_frames(
    psk: [u8; 32],
    payload: &[u8],
    name: &str,
    tiles: usize,
    max_wire: Option<i64>,
    overhead: Option<f64>,
) -> Result<Vec<RgbImage>> {
    let frame_payload_size = match max_wire {
        None => BROADCAST_SYMBOL_SIZE,
        Some(mw) => symbol_size_for_max_wire(mw as usize)?,
    };
    let extra_overhead = overhead.unwrap_or(DEFAULT_OVERHEAD);

    let on_terminal = std::io::stderr().is_terminal();
    let source_symbols_count = payload.len().div_ceil(frame_payload_size);
    let estimated_total_frames = source_symbols_count + (source_symbols_count as f64 * extra_overhead) as usize + 1;

    let transport_limits = Capabilities {
        width: 1080,
        height: 1080,
        max_fps: 30,
        cell_size: 12,
    };
    let mut custom_transport = CaptureTransport {
        inner_transport: LoopbackTransport::new(transport_limits),
        rendered_count: 0,
        should_show: on_terminal,
        estimated_total: estimated_total_frames,
    };
    
    {
        let mut sender_guy = BroadcastSender::new(
            &mut custom_transport,
            crypto::generate_identity(),
            psk,
            frame_payload_size,
            extra_overhead,
            Box::new(now_secs),
        );
        sender_guy.send_data(payload, name, LEVEL_SPEED)?;
    }
    if on_terminal {
        eprintln!(
            "\r  QR-encoded {} packets (100%)          ",
            custom_transport.rendered_count
        );
    }

    let mut encoded_qr_images: Vec<RgbImage> = Vec::new();
    while let Ok(wire_bytes) = custom_transport.capture_frame() {
        encoded_qr_images.push(qr::encode(&wire_bytes, 8, 4, "m")?);
    }

    if tiles > 1 {
        let tiles_per_frame = tiles * tiles;
        let beacon_image = encoded_qr_images[0].clone();
        let data_images = &encoded_qr_images[1..];
        let mut grouped_images = vec![beacon_image];
        for tiled_chunk in data_images.chunks(tiles_per_frame) {
            grouped_images.push(qr::compose_tiles(tiled_chunk, tiles)?);
        }
        encoded_qr_images = grouped_images;
    }

    Ok(encoded_qr_images)
}

/// Convert frames to video file on disk.
fn render_broadcast(
    psk: [u8; 32],
    payload: &[u8],
    path: &std::path::Path,
    name: &str,
    fps: u32,
    tiles: usize,
    max_wire: Option<i64>,
    overhead: Option<f64>,
) -> Result<usize> {
    let on_terminal = std::io::stderr().is_terminal();
    let all_frames = build_broadcast_frames(psk, payload, name, tiles, max_wire, overhead)?;

    let max_height = all_frames.iter().map(|f| f.height()).max().unwrap_or(0);
    let max_width = all_frames.iter().map(|f| f.width()).max().unwrap_or(0);
    let mut mp4_file_writer = Mp4Writer::new(path, fps, max_width, max_height)?;
    let total_frames = all_frames.len();
    
    for (frame_idx, frame_img) in all_frames.iter().enumerate() {
        if on_terminal && (frame_idx + 1).is_multiple_of(100) {
            eprint!("\r  writing video: {}/{total_frames} frames", frame_idx + 1);
            let _ = std::io::stderr().flush();
        }
        mp4_file_writer.write(frame_img)?;
    }
    mp4_file_writer.finish()?;
    if on_terminal {
        eprintln!("\r  wrote {total_frames} video frames -> {}", path.display());
    }
    Ok(total_frames)
}

/// Show the QR loop live in a UI window.
fn stream_live(frames: &[RgbImage], fps: u32) -> Result<()> {
    let max_width = frames.iter().map(|f| f.width()).max().unwrap_or(0) as usize;
    let max_height = frames.iter().map(|f| f.height()).max().unwrap_or(0) as usize;

    let mut display_window = minifb::Window::new(
        "Cypher live broadcast (ESC/q to stop)",
        max_width,
        max_height,
        minifb::WindowOptions {
            resize: true,
            scale_mode: minifb::ScaleMode::AspectRatioStretch,
            ..minifb::WindowOptions::default()
        },
    )
    .map_err(|_| {
        anyhow::anyhow!("no windowing environment found for live display")
    })?;

    let time_per_frame = Duration::from_secs_f64(1.0 / fps as f64);
    loop {
        for current_frame in frames {
            if !display_window.is_open()
                || display_window.is_key_down(minifb::Key::Escape)
                || display_window.is_key_down(minifb::Key::Q)
            {
                return Ok(());
            }
            let mut screen_buffer = vec![0x00FF_FFFFu32; max_width * max_height];
            let (frame_w, frame_h) = (current_frame.width() as usize, current_frame.height() as usize);
            let (offset_x, offset_y) = ((max_width - frame_w) / 2, (max_height - frame_h) / 2);
            for (px_x, px_y, rgb_pixel) in current_frame.enumerate_pixels() {
                let [red_val, green_val, blue_val] = rgb_pixel.0;
                screen_buffer[(offset_y + px_y as usize) * max_width + offset_x + px_x as usize] =
                    (u32::from(red_val) << 16) | (u32::from(green_val) << 8) | u32::from(blue_val);
            }
            let _ = display_window.update_with_buffer(&screen_buffer, max_width, max_height);
            std::thread::sleep(time_per_frame);
        }
    }
}

/// Capture live frames from camera and decode them.
fn receive_camera(args: &ReceiveArgs, psk: [u8; 32]) -> Result<()> {
    let reading_from_file = !args.source.chars().all(|c| c.is_ascii_digit());
    let w: u32 = 1280;
    let h: u32 = 720;

    let mut receiver_guy = BroadcastReceiver::new(psk, None, "sender", true, None, Box::new(now_secs));

    let mut live_window = minifb::Window::new(
        "Cypher live decode (ESC/q to quit)",
        w as usize,
        h as usize,
        minifb::WindowOptions::default(),
    )
    .ok();
    if live_window.is_none() {
        eprintln!("(no display window - terminal mode; Ctrl-C to quit)");
    }

    let on_terminal = std::io::stderr().is_terminal();
    let mut last_seen_time = Instant::now();
    let mut start_time: Option<Instant> = None;
    let mut auth_fails: usize = 0;
    let mut previous_status = String::new();
    let mut loop_count: u32 = 0;

    loop {
        let frame_source: Box<dyn Iterator<Item = RgbImage>> = if reading_from_file {
            Box::new(
                read_frames(Path::new(&args.source))
                    .with_context(|| format!("opening {}", args.source))?,
            )
        } else {
            Box::new(
                camera_frames(&args.source, w, h)
                    .with_context(|| format!("opening camera {}", args.source))?,
            )
        };

        for raw_frame in frame_source {
            let detected_codes = qr::decode_all(&raw_frame);
            let is_locked = !detected_codes.is_empty();
            if is_locked {
                last_seen_time = Instant::now();
            }
            let process_result = receiver_guy
                .on_codes(detected_codes)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if process_result == "auth-failed" {
                auth_fails += 1;
            }
            if start_time.is_none() && receiver_guy.packets_seen() > 0 {
                start_time = Some(Instant::now());
            }

            if receiver_guy.complete {
                let output_bytes = receiver_guy.data()?;
                let transfer_name = if receiver_guy.transfer_name.is_empty() {
                    "received.bin"
                } else {
                    &receiver_guy.transfer_name
                };
                let target_path = safe_dest(&args.out, transfer_name);
                std::fs::write(&target_path, &output_bytes)
                    .with_context(|| format!("writing {}", target_path.display()))?;
                
                let elapsed_seconds = start_time.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
                let speed_text = if elapsed_seconds > 0.0 {
                    format!(
                        " in {elapsed_seconds:.1}s ({:.1} KB/s)",
                        output_bytes.len() as f64 / elapsed_seconds / 1024.0
                    )
                } else {
                    String::new()
                };
                if on_terminal {
                    eprintln!();
                }
                println!("COMPLETE: {} bytes{speed_text} -> {}", output_bytes.len(), target_path.display());
                return Ok(());
            }

            let status_text = if auth_fails >= 3 && receiver_guy.packets_seen() == 0 {
                "WRONG PASSWORD - frames found but could not decrypt. Check phrase".to_string()
            } else if !is_locked {
                "searching...".to_string()
            } else {
                let received_packets = receiver_guy.packets_seen();
                let mut status_line = format!("reassembling: {received_packets} packets collected");
                if let Some(t) = start_time {
                    let elapsed_time = t.elapsed().as_secs_f64();
                    if elapsed_time > 1.0 && received_packets > 1 {
                        let packets_per_sec = received_packets as f64 / elapsed_time;
                        let kilobytes_per_sec = packets_per_sec * receiver_guy.symbol_size().unwrap_or(0) as f64 / 1024.0;
                        status_line += &format!(" | {packets_per_sec:.1} pk/s ~ {kilobytes_per_sec:.1} KB/s");
                    }
                }
                status_line
            };

            if let Some(w_win) = live_window.as_mut() {
                if !w_win.is_open()
                    || w_win.is_key_down(minifb::Key::Escape)
                    || w_win.is_key_down(minifb::Key::Q)
                {
                    if on_terminal {
                        eprintln!();
                    }
                    return Ok(());
                }
                let mut display_frame = raw_frame.clone();
                let border_color = if is_locked {
                    Rgb([0u8, 220, 0])
                } else {
                    Rgb([150u8, 150, 150])
                };
                let border_thickness = if is_locked { 4 } else { 1 };
                let (disp_w, disp_h) = (display_frame.width(), display_frame.height());
                for border_idx in 0..border_thickness {
                    imageproc::drawing::draw_hollow_rect_mut(
                        &mut display_frame,
                        imageproc::rect::Rect::at(border_idx, border_idx).of_size(
                            disp_w.saturating_sub(2 * border_idx as u32).max(1),
                            disp_h.saturating_sub(2 * border_idx as u32).max(1),
                        ),
                        border_color,
                    );
                }
                let window_buffer: Vec<u32> = display_frame
                    .pixels()
                    .map(|p| {
                        let [r, g, b] = p.0;
                        (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b)
                    })
                    .collect();
                let _ = w_win.update_with_buffer(&window_buffer, display_frame.width() as usize, display_frame.height() as usize);
            }

            let status_key = status_text.split(" | ").next().unwrap_or(&status_text).to_string();
            if on_terminal {
                eprint!("\r{status_text}\x1b[K");
                let _ = std::io::stderr().flush();
            } else if status_key != previous_status {
                eprintln!("{status_text}");
            }
            previous_status = status_key;

            if let Some(timeout) = args.timeout {
                if last_seen_time.elapsed().as_secs_f64() > timeout {
                    if on_terminal {
                        eprintln!();
                    }
                    bail!(
                        "timed out: no QR decoded for {timeout:.0}s ({} packets collected)",
                        receiver_guy.packets_seen()
                    );
                }
            }
        }

        if !reading_from_file {
            break;
        }
        loop_count += 1;
        if loop_count > 8 {
            break;
        }
    }

    if on_terminal {
        eprintln!();
    }
    bail!(
        "ended early: need more frames (only got {} packets)",
        receiver_guy.packets_seen()
    );
}
