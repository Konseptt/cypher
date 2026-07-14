//! video generator and loader using ffmpeg under the hood.
//! We center our QR frames on a white canvas and stream them to ffmpeg to output an mp4.

use std::io::Write;
use std::path::Path;
use std::process::ChildStdin;

use ffmpeg_sidecar::child::FfmpegChild;
use ffmpeg_sidecar::command::FfmpegCommand;
use image::{Rgb, RgbImage};

/// Decodes any video file into raw RGB frame images.
/// Spawns ffmpeg in the background to pipe raw video bytes back.
pub fn read_frames(file_path: &Path) -> anyhow::Result<impl Iterator<Item = RgbImage>> {
    ffmpeg_sidecar::download::auto_download()?;
    let mut ffmpeg_proc = FfmpegCommand::new()
        .hide_banner()
        .input(file_path.to_string_lossy())
        .rawvideo() // output raw rgb24 format
        .spawn()?;
    let event_iterator = ffmpeg_proc.iter()?;
    Ok(FrameIter {
        _child: ffmpeg_proc,
        iterator_box: Box::new(event_iterator.filter_frames()),
    })
}

/// Grabs frames from a webcam source.
/// On macOS, uses avfoundation under the hood.
pub fn camera_frames(
    dev_source: &str,
    w: u32,
    h: u32,
) -> anyhow::Result<impl Iterator<Item = RgbImage>> {
    ffmpeg_sidecar::download::auto_download()?;
    let mut ffmpeg_proc = FfmpegCommand::new()
        .hide_banner()
        .format("avfoundation")
        .args(["-framerate", "30"])
        .args(["-video_size", &format!("{w}x{h}")])
        .input(dev_source)
        .rawvideo()
        .spawn()?;
    let event_iterator = ffmpeg_proc.iter()?;
    Ok(FrameIter {
        _child: ffmpeg_proc,
        iterator_box: Box::new(event_iterator.filter_frames()),
    })
}

struct FrameIter {
    _child: FfmpegChild,
    iterator_box: Box<dyn Iterator<Item = ffmpeg_sidecar::event::OutputVideoFrame>>,
}

impl Iterator for FrameIter {
    type Item = RgbImage;
    fn next(&mut self) -> Option<RgbImage> {
        let f = self.iterator_box.next()?;
        RgbImage::from_raw(f.width, f.height, f.data)
    }
}

/// Helper to write frames to a new H.264 MP4 file.
pub struct Mp4Writer {
    ffmpeg_proc: FfmpegChild,
    pipe_stdin: Option<ChildStdin>,
    canvas_w: u32,
    canvas_h: u32,
    pixel_buffer: Vec<u8>,
}

impl Mp4Writer {
    /// Spawn ffmpeg and prepare to receive raw frames on stdin.
    pub fn new(out_path: &Path, frames_per_sec: u32, w: u32, h: u32) -> anyhow::Result<Self> {
        ffmpeg_sidecar::download::auto_download()?;
        let mut ffmpeg_proc = FfmpegCommand::new()
            .hide_banner()
            .overwrite()
            .format("rawvideo")
            .args(["-pixel_format", "rgb24"])
            .size(w, h)
            .rate(frames_per_sec as f32)
            .input("-") // read from stdin
            .codec_video("libx264")
            .pix_fmt("yuv420p")
            .output(out_path.to_string_lossy())
            .spawn()?;
        let stdin = ffmpeg_proc
            .take_stdin()
            .ok_or_else(|| anyhow::anyhow!("ffmpeg stdin is not available"))?;
        Ok(Self {
            ffmpeg_proc,
            pipe_stdin: Some(stdin),
            canvas_w: w,
            canvas_h: h,
            pixel_buffer: Vec::with_capacity((w * h * 3) as usize),
        })
    }

    /// Paste our frame image onto a white canvas and stream it to ffmpeg.
    pub fn write(&mut self, frame_image: &RgbImage) -> anyhow::Result<()> {
        if frame_image.width() > self.canvas_w || frame_image.height() > self.canvas_h {
            anyhow::bail!(
                "frame size {}x{} is too big for canvas {}x{}",
                frame_image.width(),
                frame_image.height(),
                self.canvas_w,
                self.canvas_h
            );
        }
        let mut white_canvas = RgbImage::from_pixel(self.canvas_w, self.canvas_h, Rgb([255, 255, 255]));
        let offset_x = ((self.canvas_w - frame_image.width()) / 2) as i64;
        let offset_y = ((self.canvas_h - frame_image.height()) / 2) as i64;
        image::imageops::replace(&mut white_canvas, frame_image, offset_x, offset_y);
        
        self.pixel_buffer.clear();
        self.pixel_buffer.extend_from_slice(white_canvas.as_raw());
        self.pipe_stdin
            .as_mut()
            .expect("stdin was closed early")
            .write_all(&self.pixel_buffer)?;
        Ok(())
    }

    /// Tell ffmpeg we are done writing frames and wait for it to exit.
    pub fn finish(mut self) -> anyhow::Result<()> {
        self.pipe_stdin.take(); // dropping stdin triggers EOF so ffmpeg wraps up
        let exit_status = self.ffmpeg_proc.wait()?;
        if !exit_status.success() {
            anyhow::bail!("ffmpeg failed: {exit_status}");
        }
        Ok(())
    }
}
