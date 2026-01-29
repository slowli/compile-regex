//! General-purpose utils.

pub use self::stack::Stack;

mod stack;

/// Version of `try!` / `?` that can be used in const fns.
macro_rules! const_try {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) => return Err(err),
        }
    };
}

pub(crate) const fn is_meta_char(ch: u8) -> bool {
    matches!(
        ch,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
            | b'#'
            | b'&'
            | b'-'
            | b'~'
    )
}

pub(crate) const fn is_escapable_char(ch: u8) -> bool {
    !matches!(ch, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'<' | b'>')
}

const UTF8_CONTINUATION_MASK: u8 = 0b1100_0000;
const UTF8_CONTINUATION_MARKER: u8 = 0b1000_0000;

pub(crate) const fn split_first_char(bytes: &[u8], mut pos: usize) -> Option<(char, usize)> {
    if pos >= bytes.len() {
        return None;
    }

    let mut codepoint = bytes[pos] as u32;
    pos += 1;
    match codepoint {
        0..=0x7f => {
            // single-byte codepoint; do nothing
        }
        0b1100_0000..=0b1101_1111 => {
            // 2-byte codepoint
            codepoint = ((codepoint & 0b0001_1111) << 6) + (bytes[pos] as u32 & 0b0011_1111);
            pos += 1;
        }
        0b1110_0000..=0b1110_1111 => {
            // 3-byte codepoint
            codepoint = ((codepoint & 0b0000_1111) << 12)
                + ((bytes[pos] as u32 & 0b0011_1111) << 6)
                + (bytes[pos + 1] as u32 & 0b0011_1111);
            pos += 2;
        }
        0b1111_0000..=0b1111_0111 => {
            // 4-byte codepoint
            codepoint = ((codepoint & 0b0000_1111) << 18)
                + ((bytes[pos] as u32 & 0b0011_1111) << 12)
                + ((bytes[pos + 1] as u32 & 0b0011_1111) << 6)
                + (bytes[pos + 2] as u32 & 0b0011_1111);
            pos += 3;
        }
        _ => panic!("invalid UTF-8 string"),
    }
    match char::from_u32(codepoint) {
        Some(ch) => Some((ch, pos)),
        None => None,
    }
}

pub(crate) const fn ceil_char_boundary(bytes: &[u8], mut pos: usize) -> usize {
    assert!(pos <= bytes.len());

    while pos < bytes.len() && bytes[pos] & UTF8_CONTINUATION_MASK == UTF8_CONTINUATION_MARKER {
        pos += 1;
    }
    pos
}

pub(crate) const fn is_char_boundary(ch: u8) -> bool {
    ch & UTF8_CONTINUATION_MASK != UTF8_CONTINUATION_MARKER
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    const FUZZ_SAMPLE_COUNT: usize = 1_000_000;

    #[test]
    fn splitting_first_char_minifuzz() {
        const RNG_SEED: u64 = 123;

        let mut rng = StdRng::seed_from_u64(RNG_SEED);
        for _ in 0..FUZZ_SAMPLE_COUNT {
            let s: String = (0..2).map(|_| rng.random::<char>()).collect();
            let (first_ch, pos) = split_first_char(s.as_bytes(), 0).unwrap();
            let mut chars = s.char_indices();
            assert_eq!(first_ch, chars.next().unwrap().1);
            assert_eq!(pos, chars.next().unwrap().0);
        }
    }

    #[test]
    fn char_boundary_minifuzz() {
        const RNG_SEED: u64 = 321;

        let mut rng = StdRng::seed_from_u64(RNG_SEED);
        for _ in 0..FUZZ_SAMPLE_COUNT {
            let s: String = (0..5).map(|_| rng.random::<char>()).collect();
            let pos = rng.random_range(0..=s.len());
            let got = ceil_char_boundary(s.as_bytes(), pos);
            assert!(got >= pos);
            assert!(s.is_char_boundary(got));
            for i in pos..got {
                assert!(!s.is_char_boundary(i));
            }
        }
    }
}
