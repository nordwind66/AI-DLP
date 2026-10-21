//! Byte-offset <-> code-point-offset conversion for the API layer.

/// Precomputed map from UTF-8 byte offsets to Unicode code point (and UTF-16 unit) offsets.
/// Built lazily only when an API response has to be rendered.
pub struct OffsetMap {
    /// byte offset -> char index for every char boundary; `u32::MAX` for non-boundaries.
    char_idx: Vec<u32>,
    utf16_idx: Vec<u32>,
    pub char_len: usize,
}

impl OffsetMap {
    pub fn new(text: &str) -> Self {
        let mut char_idx = vec![u32::MAX; text.len() + 1];
        let mut utf16_idx = vec![u32::MAX; text.len() + 1];
        let (mut c, mut u) = (0u32, 0u32);
        for (b, ch) in text.char_indices() {
            char_idx[b] = c;
            utf16_idx[b] = u;
            c += 1;
            u += ch.len_utf16() as u32;
        }
        char_idx[text.len()] = c;
        utf16_idx[text.len()] = u;
        OffsetMap { char_idx, utf16_idx, char_len: c as usize }
    }
    /// Convert a byte offset to a code point index. Non-boundary offsets round down.
    pub fn char_offset(&self, byte: usize) -> usize {
        let mut b = byte.min(self.char_idx.len() - 1);
        while self.char_idx[b] == u32::MAX {
            b -= 1;
        }
        self.char_idx[b] as usize
    }
    pub fn utf16_offset(&self, byte: usize) -> usize {
        let mut b = byte.min(self.utf16_idx.len() - 1);
        while self.utf16_idx[b] == u32::MAX {
            b -= 1;
        }
        self.utf16_idx[b] as usize
    }
}

/// Convert code point offsets (as produced by Python) into byte offsets in one linear pass.
/// `char_offsets` need not be sorted. Out-of-range offsets clamp to `text.len()`.
pub fn char_to_byte_offsets(text: &str, char_offsets: &[usize]) -> Vec<usize> {
    let mut table: Vec<usize> = Vec::with_capacity(text.len() / 2 + 2);
    for (b, _) in text.char_indices() {
        table.push(b);
    }
    table.push(text.len());
    char_offsets.iter().map(|&c| table[c.min(table.len() - 1)]).collect()
}

/// Largest char boundary `<= i`.
pub fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Smallest char boundary `>= i`.
pub fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_text_offsets() {
        let t = "张三😀a\nb";
        let m = OffsetMap::new(t);
        assert_eq!(m.char_len, 6);
        assert_eq!(m.char_offset(0), 0);
        assert_eq!(m.char_offset(3), 1);
        assert_eq!(m.char_offset(6), 2); // emoji start
        assert_eq!(m.utf16_offset(10), 4); // after emoji (2 utf16 units)
        assert_eq!(m.char_offset(t.len()), 6);
        assert_eq!(char_to_byte_offsets(t, &[0, 1, 2, 3, 6]), vec![0, 3, 6, 10, 13]);
    }
}
