//! Decoded pixels.

/// An image of 8-bit RGBA pixels, row-major, with no padding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Image {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Image {
    /// The image of `rgba`, or `None` when its length is not
    /// `width * height * 4` or a side is 0.
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> Option<Image> {
        let len = usize::try_from(width)
            .ok()?
            .checked_mul(usize::try_from(height).ok()?)?
            .checked_mul(4)?;
        (width > 0 && height > 0 && rgba.len() == len).then_some(Image {
            width,
            height,
            rgba,
        })
    }

    /// The width in pixels.
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// The height in pixels.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// The pixels: red, green, blue and alpha for each.
    pub fn rgba(&self) -> &[u8] {
        &self.rgba
    }

    /// The pixels, taking the image.
    pub fn into_rgba(self) -> Vec<u8> {
        self.rgba
    }

    /// Whether every pixel is fully opaque.
    pub fn is_opaque(&self) -> bool {
        self.rgba.chunks_exact(4).all(|p| p.get(3) == Some(&255))
    }

    pub(crate) fn width_usize(&self) -> usize {
        usize::try_from(self.width).unwrap_or(0)
    }

    pub(crate) fn height_usize(&self) -> usize {
        usize::try_from(self.height).unwrap_or(0)
    }
}

/// `f` over `b` at opacity `a`, in 8-bit sRGB with rounding:
/// `(f * a + b * (255 - a) + 127) / 255`.
pub(crate) fn blend(f: u8, b: u8, a: u8) -> u8 {
    let (f, b, a) = (u32::from(f), u32::from(b), u32::from(a));
    let sum = f
        .wrapping_mul(a)
        .wrapping_add(b.wrapping_mul(255u32.wrapping_sub(a)))
        .wrapping_add(127);
    u8::try_from(sum / 255).unwrap_or(u8::MAX)
}
