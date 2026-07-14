//! Core stuff for rendering and reading QR codes.
//! Basically converts raw bytes to a QR image and back.

use image::{GrayImage, Rgb, RgbImage};
use thiserror::Error;
use zxingcpp::{BarcodeFormat, ImageFormat, ImageView};

pub use cypher_core::frame::{max_payload, MAX_WIRE};

/// Errors we might hit if the QR engine crashes or if we pass dumb values.
#[derive(Debug, Error)]
pub enum QRError {
    #[error("{0}")]
    Value(String),
    #[error("zxing: {0}")]
    Zxing(#[from] zxingcpp::Error),
}

/// Turn raw byte data into a black and white QR code image.
/// `pixel_pitch` is how big each QR square is in pixels.
/// `border_padding` is the white quiet zone padding around it.
pub fn encode(input_bytes: &[u8], pixel_pitch: u32, border_padding: u32, error_correction: &str) -> Result<RgbImage, QRError> {
    let barcode_obj = zxingcpp::create(BarcodeFormat::QRCode)
        .options(format!("ec_level:{}", error_correction.to_uppercase()))
        .from_slice(input_bytes)?;
    
    // zxing renders a gray image first.
    let grayscale_img: GrayImage = (&barcode_obj.to_image_with(&zxingcpp::write().scale(pixel_pitch as i32))?).into();
    let mut rgb_img = gray_to_rgb(&grayscale_img);
    
    // Pad extra border modules if they wanted a fat white frame.
    if border_padding > 4 {
        rgb_img = pad_white(&rgb_img, (border_padding - 4) * pixel_pitch);
    }
    Ok(rgb_img)
}

/// Tries to decode the very first QR code it spots in an image.
pub fn decode(img: &RgbImage) -> Option<Vec<u8>> {
    decode_all(img).into_iter().next()
}

/// Finds and decodes every single QR code in the image (for tiled layouts).
pub fn decode_all(img: &RgbImage) -> Vec<Vec<u8>> {
    let image_view = match ImageView::from_slice(
        img.as_raw(),
        img.width(),
        img.height(),
        ImageFormat::RGB,
    ) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    match zxingcpp::read().from(&image_view) {
        Ok(detected_barcodes) => detected_barcodes.iter().map(|c| c.bytes()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Paste multiple QR images together into a grid (like a collage).
pub fn compose_tiles(grid_images: &[RgbImage], grid_size: usize) -> Result<RgbImage, QRError> {
    if !(1..=3).contains(&grid_size) {
        return Err(QRError::Value(format!("grid_size must be 1..3, got {}", grid_size)));
    }
    if !(1..=grid_size * grid_size).contains(&grid_images.len()) {
        return Err(QRError::Value(format!(
            "need 1..{} images for a {}x{} grid, got {}",
            grid_size * grid_size,
            grid_size,
            grid_size,
            grid_images.len()
        )));
    }
    if grid_size == 1 {
        return Ok(grid_images[0].clone());
    }
    let max_width = grid_images.iter().map(|i| i.width()).max().unwrap();
    let max_height = grid_images.iter().map(|i| i.height()).max().unwrap();
    let mut full_canvas = RgbImage::from_pixel(
        max_width * grid_size as u32,
        max_height * grid_size as u32,
        Rgb([255, 255, 255]),
    );
    for (index, image_tile) in grid_images.iter().enumerate() {
        let (row_idx, col_idx) = (index / grid_size, index % grid_size);
        let pos_x = col_idx as u32 * max_width + (max_width - image_tile.width()) / 2;
        let pos_y = row_idx as u32 * max_height + (max_height - image_tile.height()) / 2;
        image::imageops::replace(&mut full_canvas, image_tile, pos_x as i64, pos_y as i64);
    }
    Ok(full_canvas)
}

/// Generate multiple QR codes and stitch them into a grid layout.
pub fn encode_tiled(
    wire_payloads: &[&[u8]],
    grid_size: usize,
    pixel_pitch: u32,
    border_padding: u32,
    error_correction: &str,
) -> Result<RgbImage, QRError> {
    let rendered_tiles: Result<Vec<RgbImage>, QRError> =
        wire_payloads.iter().map(|w| encode(w, pixel_pitch, border_padding, error_correction)).collect();
    compose_tiles(&rendered_tiles?, grid_size)
}

fn gray_to_rgb(gray: &GrayImage) -> RgbImage {
    let mut rgb = RgbImage::new(gray.width(), gray.height());
    for (dst, src) in rgb.pixels_mut().zip(gray.pixels()) {
        let v = src.0[0];
        *dst = Rgb([v, v, v]);
    }
    rgb
}

fn pad_white(img: &RgbImage, pad: u32) -> RgbImage {
    let mut canvas = RgbImage::from_pixel(
        img.width() + 2 * pad,
        img.height() + 2 * pad,
        Rgb([255, 255, 255]),
    );
    image::imageops::replace(&mut canvas, img, pad as i64, pad as i64);
    canvas
}

/// Packages the beacon data into a frame and spits it out as a QR image.
pub fn render_receiver_beacon_frame(rbea_wire: &[u8]) -> Result<RgbImage, QRError> {
    use cypher_core::frame::{Frame, RECEIVER_BEACON};
    let frame = Frame::new(0, RECEIVER_BEACON, rbea_wire.to_vec())
        .expect("receiver-beacon frame fields are in range");
    encode(&frame.encode(), 8, 4, "m")
}

/// Grabs a receiver beacon out of a QR image.
pub fn parse_receiver_beacon_frame(
    grid: &RgbImage,
    clock: impl Fn() -> f64,
) -> Result<cypher_core::beacon::ReceiverBeacon, cypher_core::beacon::BeaconError> {
    use cypher_core::beacon::{parse_receiver_beacon, BeaconError};
    use cypher_core::frame::{Frame, RECEIVER_BEACON};
    let raw = decode(grid).ok_or(BeaconError::ReceiverWrongLength)?;
    let frame = Frame::decode(&raw).map_err(|_| BeaconError::ReceiverWrongLength)?;
    if frame.flags & RECEIVER_BEACON == 0 {
        return Err(BeaconError::ReceiverBadMagic);
    }
    parse_receiver_beacon(&frame.payload, clock)
}
