//! CRC-32 as PNG uses it (ISO 3309, reflected, polynomial 0xEDB88320)
//! and Adler-32 (RFC 1950 section 9).

/// The CRC table, built at compile time.
const CRC_TABLE: [u32; 256] = crc_table();

#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "evaluated at compile time over fixed bounds"
)]
const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
}

/// A running CRC-32.
#[derive(Clone, Copy)]
pub(crate) struct Crc(u32);

impl Crc {
    pub(crate) const fn new() -> Crc {
        Crc(0xFFFF_FFFF)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for &b in data {
            let i = usize::from((self.0 as u8) ^ b);
            self.0 = CRC_TABLE.get(i).copied().unwrap_or(0) ^ (self.0 >> 8);
        }
    }

    pub(crate) const fn finish(self) -> u32 {
        !self.0
    }
}

/// The CRC-32 of `data`, as a PNG chunk carries it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc::new();
    c.update(data);
    c.finish()
}

/// The Adler-32 modulus.
const BASE: u32 = 65_521;

/// The most bytes summed before a reduction keeps `b` below 2^32.
const NMAX: usize = 5552;

/// A running Adler-32.
#[derive(Clone, Copy)]
pub(crate) struct Adler {
    a: u32,
    b: u32,
}

impl Adler {
    pub(crate) const fn new() -> Adler {
        Adler { a: 1, b: 0 }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(NMAX) {
            for &x in chunk {
                self.a = self.a.wrapping_add(u32::from(x));
                self.b = self.b.wrapping_add(self.a);
            }
            self.a = self.a.checked_rem(BASE).unwrap_or(0);
            self.b = self.b.checked_rem(BASE).unwrap_or(0);
        }
    }

    pub(crate) const fn finish(self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// The Adler-32 of `data`, as a zlib stream carries it.
pub fn adler32(data: &[u8]) -> u32 {
    let mut a = Adler::new();
    a.update(data);
    a.finish()
}
