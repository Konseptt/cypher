//! Simulation tool to make an image look like a crappy photo taken on a phone.
//! skews the corners, blurs it, and adds random noise.

use image::{Rgb, RgbImage};
use imageproc::geometric_transformations::{warp, Interpolation, Projection};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Distort the image to mimic a quick snap from a phone camera.
/// `warp_frac` = how much we mess up the corners.
/// `blur` = blur strength (must be odd number).
/// `noise` = random grain amount.
pub fn cam(img: &RgbImage, seed: u64, warp_frac: f32, blur: u32, noise: u8) -> RgbImage {
    let mut rand_gen = StdRng::seed_from_u64(seed);
    let (width_val, height_val) = (img.width() as f32, img.height() as f32);
    let max_shift = warp_frac * width_val.min(height_val);
    
    // Corners of the original image: Top-Left, Top-Right, Bottom-Right, Bottom-Left
    let original_corners = [(0.0, 0.0), (width_val, 0.0), (width_val, height_val), (0.0, height_val)];
    let mut shifted_corners = [(0.0f32, 0.0f32); 4];
    
    for (dest_pt, source_pt) in shifted_corners.iter_mut().zip(original_corners.iter()) {
        dest_pt.0 = source_pt.0 + rand_gen.gen_range(-max_shift..=max_shift);
        dest_pt.1 = source_pt.1 + rand_gen.gen_range(-max_shift..=max_shift);
    }
    
    // Map the old corners to the new warped ones.
    let mut distorted_img = match Projection::from_control_points(original_corners, shifted_corners) {
        Some(p) => warp(img, &p, Interpolation::Bilinear, Rgb([255, 255, 255])),
        None => img.clone(), // If math breaks, just return the clean image.
    };

    // Apply some Gaussian blur so the edges aren't too sharp.
    let kernel_size = blur | 1; // Make sure it's odd.
    if kernel_size > 1 {
        let blur_sigma = 0.3 * (((kernel_size - 1) as f32) * 0.5 - 1.0) + 0.8;
        distorted_img = imageproc::filter::gaussian_blur_f32(&distorted_img, blur_sigma);
    }

    // Throw some random pixel grain/noise on top.
    let noise_range = noise as i16;
    for pixel in distorted_img.pixels_mut() {
        for color_channel in pixel.0.iter_mut() {
            let new_color_val = *color_channel as i16 + rand_gen.gen_range(-noise_range..=noise_range);
            *color_channel = new_color_val.clamp(0, 255) as u8;
        }
    }
    distorted_img
}
