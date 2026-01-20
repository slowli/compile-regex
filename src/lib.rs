use core::ops;

pub use crate::{
    ast::{Ast, GroupName, Range, SyntaxSpan, SyntaxSpans},
    errors::{Error, ErrorKind},
};

mod ast;
mod errors;
#[cfg(test)]
mod tests;

macro_rules! const_try {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) => return Err(err),
        }
    };
}

const fn split_first_char(bytes: &[u8], mut pos: usize) -> Option<(char, usize)> {
    if pos >= bytes.len() {
        return None;
    }

    let mut codepoint = bytes[pos] as u32;
    pos += 1;
    match codepoint {
        0..0x7f => {
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
                + (bytes[pos] as u32 & 0b0011_1111)
                + (bytes[pos + 1] as u32 & 0b0011_1111);
            pos += 2;
        }
        0b1111_0000..=0b1111_0111 => {
            // 4-byte codepoint
            codepoint = ((codepoint & 0b0000_1111) << 18)
                + (bytes[pos] as u32 & 0b0011_1111)
                + (bytes[pos + 1] as u32 & 0b0011_1111)
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

const fn is_meta_char(ch: u8) -> bool {
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

const fn is_escapable_char(ch: u8) -> bool {
    !matches!(ch, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'<' | b'>')
}

#[derive(Debug)]
enum PrimitiveKind {
    Literal(char),
    NotLiteral,
}

#[derive(Debug)]
struct Flags {
    is_empty: bool,
    ignore_whitespace: Option<bool>,
}

#[derive(Debug)]
struct ParseState<'a, const CAP: usize = 0> {
    /// Always a valid UTF-8 string.
    regex_bytes: &'a [u8],
    pos: usize,
    group_depth: usize,
    is_empty_last_item: bool,
    spans: Option<SyntaxSpans<CAP>>,
}

impl<'a> ParseState<'a> {
    const fn new(regex: &'a str) -> Self {
        Self::custom(regex, false)
    }
}

impl<'a, const CAP: usize> ParseState<'a, CAP> {
    const fn custom(regex: &'a str, with_ast: bool) -> Self {
        Self {
            regex_bytes: regex.as_bytes(),
            pos: 0,
            group_depth: 0,
            is_empty_last_item: true,
            spans: if with_ast {
                Some(SyntaxSpans::new())
            } else {
                None
            },
        }
    }

    const fn ascii_char_at(&self, pos: usize) -> Option<u8> {
        if pos >= self.regex_bytes.len() {
            None
        } else {
            let ch = self.regex_bytes[pos];
            if ch <= 0x7f {
                Some(ch)
            } else {
                None
            }
        }
    }

    const fn ascii_char(&self) -> Option<u8> {
        self.ascii_char_at(self.pos)
    }

    const fn error(&self, kind: ErrorKind, start: usize) -> Error {
        let end = if self.pos <= self.regex_bytes.len() {
            self.pos // FIXME: may not be on char boundary; increase in this case
        } else {
            self.regex_bytes.len()
        };
        kind.with_position(start..end)
    }

    const fn push_ast(&mut self, start_pos: usize, node: Ast) -> Result<(), Error> {
        if let Some(spans) = &mut self.spans {
            let span = SyntaxSpan {
                node,
                range: Range::new(start_pos, self.pos),
            };
            if spans.push(span).is_err() {
                return Err(self.error(ErrorKind::AstOverflow, start_pos));
            }
        }
        Ok(())
    }

    /// Gobbles the provided bytes if they are next. Otherwise, doesn't change the state.
    const fn gobble(&mut self, bytes: &[u8]) -> bool {
        let mut i = 0;
        while i < bytes.len()
            && self.pos + i < self.regex_bytes.len()
            && bytes[i] == self.regex_bytes[self.pos + i]
        {
            i += 1;
        }
        if i == bytes.len() {
            // All bytes have matched
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    const fn gobble_any(&mut self, needles: &[&[u8]]) -> bool {
        let mut i = 0;
        while i < needles.len() {
            let matched = self.gobble(needles[i]);
            if matched {
                return true;
            }
            i += 1;
        }
        false
    }

    const fn matches(&self, range: ops::Range<usize>, needle: &[u8]) -> bool {
        if range.end - range.start != needle.len() {
            return false;
        }
        if range.end > self.regex_bytes.len() {
            return false;
        }

        let mut i = 0;
        while i < needle.len() && self.regex_bytes[range.start + i] == needle[i] {
            i += 1;
        }
        i == needle.len()
    }

    const fn matches_any(&self, range: ops::Range<usize>, needles: &[&[u8]]) -> bool {
        let mut i = 0;
        while i < needles.len() {
            if self.matches(range.start..range.end, needles[i]) {
                return true;
            }
            i += 1;
        }
        false
    }

    const fn parse_uncounted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        // `pos` is currently at one of `?`, `*` or `+` (all ASCII chars)
        self.pos += 1;
        if self.is_empty_last_item {
            return Err(self.error(ErrorKind::MissingRepetition, self.pos - 1));
        }
        // Parse optional non-greedy marker `?`
        self.gobble(b"?");

        const_try!(self.push_ast(start_pos, Ast::UncountedRepetition));
        Ok(())
    }

    const fn parse_counted_repetition(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'{');
        self.pos += 1; // gobble '{'

        if self.is_empty_last_item {
            return Err(self.error(ErrorKind::MissingRepetition, start_pos));
        }
        // Minimum or exact count
        let (min_count, min_count_span) = const_try!(self.parse_decimal());

        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(ErrorKind::UnfinishedRepetition, start_pos)),
        };
        let max_count_span = if current_char == b',' {
            self.pos += 1;
            // Maximum count
            let (max_count, max_count_span) = const_try!(self.parse_decimal());
            if max_count < min_count {
                return Err(self.error(ErrorKind::InvalidRepetitionRange, start_pos));
            }
            Some(max_count_span)
        } else {
            None
        };

        if matches!(self.ascii_char(), Some(b'}')) {
            self.pos += 1;
            // Parse optional non-greedy marker `?`
            self.gobble(b"?");
            const_try!(self.push_ast(
                start_pos,
                Ast::CountedRepetition {
                    min_or_exact_count: min_count_span,
                    max_count: max_count_span,
                }
            ));
            Ok(())
        } else {
            Err(self.error(ErrorKind::UnfinishedRepetition, start_pos))
        }
    }

    const fn parse_decimal(&mut self) -> Result<(u32, Range), Error> {
        let start_pos = self.pos;
        let mut pos = self.pos;
        let mut decimal = 0_u32;
        while pos < self.regex_bytes.len() && self.regex_bytes[pos].is_ascii_digit() {
            let new_decimal = match decimal.checked_mul(10) {
                Some(dec) => dec,
                None => return Err(ErrorKind::InvalidDecimal.with_position(start_pos..pos + 1)),
            };
            decimal = match new_decimal.checked_add((self.regex_bytes[pos] - b'0') as u32) {
                Some(dec) => dec,
                None => return Err(ErrorKind::InvalidDecimal.with_position(start_pos..pos + 1)),
            };
            pos += 1;
        }

        if pos == self.pos {
            Err(self.error(ErrorKind::EmptyDecimal, start_pos))
        } else {
            self.pos = pos;
            Ok((decimal, Range::new(start_pos, pos)))
        }
    }

    const fn parse_primitive(&mut self, ch: char, next_pos: usize) -> Result<(), Error> {
        match ch {
            '\\' => {
                const_try!(self.parse_escape());
                Ok(())
            }
            '.' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::Dot));
                Ok(())
            }
            '^' | '$' => {
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::LineAssertion));
                Ok(())
            }
            _ => {
                self.pos = next_pos;
                Ok(())
            }
        }
    }

    const fn parse_escape(&mut self) -> Result<PrimitiveKind, Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'\\');
        self.pos += 1;

        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(ErrorKind::UnfinishedEscape, start_pos)),
        };
        // Gobble the escaped single ASCII char
        self.pos += 1;

        match current_char {
            b'0'..=b'9' => Err(self.error(ErrorKind::UnsupportedBackref, start_pos)),
            b'x' | b'u' | b'U' => {
                let ch = const_try!(self.parse_hex_escape(start_pos, current_char));
                const_try!(self.push_ast(start_pos, Ast::HexEscape));
                Ok(PrimitiveKind::Literal(ch))
            }
            b'p' | b'P' => Err(self.error(ErrorKind::UnicodeClassesNotSupported, start_pos)),
            b'd' | b's' | b'w' | b'D' | b'S' | b'W' => {
                const_try!(self.push_ast(start_pos, Ast::PerlClass));
                Ok(PrimitiveKind::NotLiteral)
            }

            b'n' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\n'))
            }
            b't' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\t'))
            }
            b'r' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\r'))
            }
            b'a' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x07'))
            }
            b'f' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0C'))
            }
            b'v' => {
                const_try!(self.push_ast(start_pos, Ast::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0B'))
            }

            b'A' | b'z' | b'B' | b'<' | b'>' => {
                const_try!(self.push_ast(start_pos, Ast::StdAssertion));
                Ok(PrimitiveKind::NotLiteral)
            }
            b'b' => {
                if matches!(self.ascii_char(), Some(b'{')) {
                    const_try!(self.try_parse_word_boundary());
                }
                Ok(PrimitiveKind::NotLiteral)
            }
            ch if is_meta_char(ch) => {
                const_try!(self.push_ast(start_pos, Ast::EscapedChar { meta: true }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            ch if is_escapable_char(ch) => {
                const_try!(self.push_ast(start_pos, Ast::EscapedChar { meta: false }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            _ => Err(self.error(ErrorKind::UnsupportedEscape, start_pos)),
        }
    }

    const fn try_parse_word_boundary(&mut self) -> Result<(), Error> {
        const fn is_valid_char(ch: u8) -> bool {
            matches!(ch, b'A'..=b'Z' | b'a'..=b'z' | b'-')
        }

        const KNOWN_BOUNDARIES: &[&[u8]] = &[b"start", b"end", b"start-half", b"end-half"];

        let mut pos = self.pos + 1; // immediately gobble the opening '{'
        let start_pos = pos;
        if pos >= self.regex_bytes.len() {
            return Err(self.error(ErrorKind::UnfinishedWordBoundary, start_pos));
        }
        if !is_valid_char(self.regex_bytes[pos]) {
            return Ok(()); // not a word boundary specifier
        }

        while pos < self.regex_bytes.len() && is_valid_char(self.regex_bytes[pos]) {
            pos += 1;
        }
        if pos == self.regex_bytes.len() || self.regex_bytes[pos] != b'}' {
            return Err(ErrorKind::UnfinishedWordBoundary.with_position(start_pos..pos));
        }

        // Check whether the boundary specification is known.
        if !self.matches_any(start_pos..pos, KNOWN_BOUNDARIES) {
            return Err(ErrorKind::UnknownWordBoundary.with_position(start_pos..pos));
        }

        self.pos = pos;
        self.push_ast(start_pos, Ast::StdAssertion)
    }

    /// Parses a hex-escaped char. The parser position is after the marker ('x', 'u' or 'U').
    const fn parse_hex_escape(&mut self, start_pos: usize, marker_ch: u8) -> Result<char, Error> {
        let current_char = match self.ascii_char() {
            Some(ch) => ch,
            None => return Err(self.error(ErrorKind::UnfinishedEscape, start_pos)),
        };
        if current_char == b'{' {
            // escape with braces, e.g., \u{123}
            self.parse_hex_brace(start_pos)
        } else {
            let expected_digits = match marker_ch {
                b'x' => 2,
                b'u' => 4,
                b'U' => 8,
                _ => unreachable!(),
            };
            self.parse_hex_digits(start_pos, expected_digits)
        }
    }

    const fn parse_hex_brace(&mut self, start_pos: usize) -> Result<char, Error> {
        self.pos += 1; // gobble '{'

        let first_digit_pos = self.pos;
        let mut hex = 0_u32;
        while self.pos < self.regex_bytes.len() && self.regex_bytes[self.pos] != b'}' {
            let digit = self.regex_bytes[self.pos];
            self.pos += 1;
            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(self.error(ErrorKind::InvalidHex, start_pos)),
            };
            if self.pos >= first_digit_pos + 8 {
                return Err(self.error(ErrorKind::NonUnicodeHex, start_pos));
            }
            // No overflow can happen due to the check above
            hex = hex * 16 + digit as u32;
        }

        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedEscape, start_pos));
        }

        // Gobble the terminating '}'
        debug_assert!(self.regex_bytes[self.pos] == b'}');
        self.pos += 1;

        if self.pos == first_digit_pos + 1 {
            Err(self.error(ErrorKind::EmptyHex, start_pos))
        } else {
            match char::from_u32(hex) {
                Some(ch) => Ok(ch),
                None => Err(self.error(ErrorKind::NonUnicodeHex, start_pos)),
            }
        }
    }

    const fn parse_hex_digits(
        &mut self,
        start_pos: usize,
        expected_digits: usize,
    ) -> Result<char, Error> {
        let first_digit_pos = self.pos;
        let mut hex = 0_u32;
        while self.pos - first_digit_pos < expected_digits {
            if self.is_eof() {
                return Err(self.error(ErrorKind::UnfinishedEscape, start_pos));
            }
            let digit = self.regex_bytes[self.pos];
            self.pos += 1; // Advance immediately to get the correct error span

            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(self.error(ErrorKind::InvalidHex, start_pos)),
            };
            // No overflow can happen.
            hex = hex * 16 + digit as u32;
        }

        match char::from_u32(hex) {
            Some(ch) => Ok(ch),
            None => Err(self.error(ErrorKind::NonUnicodeHex, start_pos)),
        }
    }

    const fn is_eof(&self) -> bool {
        self.pos == self.regex_bytes.len()
    }

    const fn parse_group_start(&mut self) -> Result<(), Error> {
        const LOOKAROUND_PREFIXES: &[&[u8]] = &[b"?=", b"?!", b"?<=", b"?<!"];
        const NAMED_PREFIXES: &[&[u8]] = &[b"?P<", b"?<"];

        // Gobble the opening '('
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'(');
        self.pos += 1;

        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedGroup, start_pos));
        }

        let is_lookaround = self.gobble_any(LOOKAROUND_PREFIXES);
        if is_lookaround {
            return Err(self.error(ErrorKind::LookaroundNotSupported, start_pos));
        }

        let name_start = self.pos;
        let is_named = self.gobble_any(NAMED_PREFIXES);
        let name = if is_named {
            let start = Range::new(name_start, self.pos);
            Some(const_try!(self.parse_capture_name(start)))
        } else {
            None
        };

        let mut flags_pos = None;
        if !is_named && self.regex_bytes[self.pos] == b'?' {
            let flags_start = self.pos;
            let flags = const_try!(self.parse_flags());
            if matches!(flags.ignore_whitespace, Some(true)) {
                panic!("whitespace control is not supported yet"); // FIXME
            }
            if !flags.is_empty {
                flags_pos = Some(Range::new(flags_start, self.pos));
            }

            let ch = self.regex_bytes[self.pos];
            debug_assert!(ch == b':' || ch == b')');

            if ch == b')' {
                // Flags for the current group.
                if flags.is_empty {
                    // Treat `(?)` as missing repetition, same as in `regex-parser`
                    return Err(self.error(ErrorKind::MissingRepetition, start_pos));
                }
                // Do not advance the pos, so that `)` is parsed as the group end and decrements the group depth.
            } else {
                self.pos += 1;
            }
        };

        const_try!(self.push_ast(
            start_pos,
            Ast::GroupStart {
                name,
                flags: flags_pos,
            }
        ));

        self.group_depth += 1; // This works fine with the standalone flags like `(?m-u)`.
        Ok(())
    }

    const fn parse_capture_name(&mut self, start: Range) -> Result<GroupName, Error> {
        const fn is_capture_char(ch: u8, is_first: bool) -> bool {
            if is_first {
                ch == b'_' || ch.is_ascii_alphabetic()
            } else {
                ch == b'_' || ch == b'.' || ch == b'[' || ch == b']' || ch.is_ascii_alphanumeric()
            }
        }

        let start_pos = self.pos;
        while self.pos < self.regex_bytes.len() && self.regex_bytes[self.pos] != b'>' {
            let ch = self.regex_bytes[self.pos];
            if ch > 0x7f {
                return Err(self.error(ErrorKind::NonAsciiCaptureName, start_pos));
            }

            let is_first = start_pos == self.pos;
            self.pos += 1;
            if !is_capture_char(ch, is_first) {
                return Err(self.error(ErrorKind::InvalidCaptureName, start_pos));
            }
        }

        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedCaptureName, start_pos));
        }
        debug_assert!(self.regex_bytes[self.pos] == b'>');
        self.pos += 1;

        Ok(GroupName {
            start,
            name: Range::new(start_pos, self.pos - 1),
            end: Range::new(self.pos - 1, self.pos),
        })
    }

    const fn parse_flags(&mut self) -> Result<Flags, Error> {
        const KNOWN_FLAGS_COUNT: usize = 7;
        const KNOWN_FLAGS: [u8; KNOWN_FLAGS_COUNT] = *b"ximsUuR";

        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'?');
        self.pos += 1;

        let mut negation = false;
        let mut flag_values = [None::<bool>; KNOWN_FLAGS_COUNT];
        let mut is_empty = true;
        while !self.is_eof() {
            let ch = self.regex_bytes[self.pos];
            if ch == b':' || ch == b')' {
                break;
            }
            self.pos += 1;

            if ch == b'-' {
                if negation {
                    return Err(self.error(ErrorKind::RepeatedFlagNegation, self.pos - 1));
                }
                negation = true;
                continue;
            }

            let mut i = 0;
            while i < KNOWN_FLAGS_COUNT {
                if ch == KNOWN_FLAGS[i] {
                    break;
                }
                i += 1;
            }
            if i == KNOWN_FLAGS_COUNT {
                return Err(self.error(ErrorKind::UnsupportedFlag, self.pos - 1));
            }

            if let Some(prev_value) = flag_values[i] {
                let err = ErrorKind::RepeatedFlag {
                    contradicting: prev_value == negation,
                };
                return Err(self.error(err, self.pos - 1));
            }
            flag_values[i] = Some(!negation);
            is_empty = false;
            negation = false;
        }

        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedFlags, start_pos));
        }
        if negation {
            return Err(self.error(ErrorKind::UnfinishedFlagsNegation, self.pos - 1));
        }

        Ok(Flags {
            is_empty,
            ignore_whitespace: flag_values[0],
        })
    }

    const fn end_group(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b')');
        self.pos += 1;

        if self.group_depth == 0 {
            return Err(self.error(ErrorKind::NonMatchingGroupEnd, start_pos));
        }
        self.group_depth -= 1;
        self.push_ast(start_pos, Ast::GroupEnd)
    }

    const fn parse_set_class(&mut self) -> Result<(), Error> {
        const_try!(self.parse_set_class_start());

        let mut set_depth = 1;
        while set_depth > 0 {
            if self.is_eof() {
                return Err(self.error(ErrorKind::UnfinishedSet, self.pos));
            }

            let op_start = self.pos;
            if self.gobble_any(&[b"&&", b"--", b"~~"]) {
                const_try!(self.push_ast(op_start, Ast::SetOp));
                continue;
            }

            let ch = self.regex_bytes[self.pos];
            match ch {
                b'[' => {
                    // Try parse the ASCII char class first. If that fails, treat it as an embedded class.
                    if self.try_parse_ascii_class() {
                        const_try!(self.push_ast(op_start, Ast::AsciiClass));
                    } else {
                        self.pos = op_start; // Restore the parser position
                        const_try!(self.parse_set_class_start());
                        set_depth += 1;
                    }
                }
                b']' => {
                    self.pos += 1;
                    const_try!(self.push_ast(op_start, Ast::SetEnd));
                    set_depth -= 1;
                }
                _ => const_try!(self.parse_set_class_range()),
            }
        }

        Ok(())
    }

    /// Parses the start of the set class, including the opening `[` and any specially handled chars
    /// (`^`, `-` and `]`).
    const fn parse_set_class_start(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'[');
        self.pos += 1;

        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedSet, start_pos));
        }

        let negation = if self.regex_bytes[self.pos] == b'^' {
            self.pos += 1;
            if self.is_eof() {
                return Err(self.error(ErrorKind::UnfinishedSet, start_pos));
            }
            Some(Range::new(self.pos - 1, self.pos))
        } else {
            None
        };
        const_try!(self.push_ast(start_pos, Ast::SetStart { negation }));

        if self.regex_bytes[self.pos] == b']' {
            // Literal ']'
            self.pos += 1;
        } else {
            // Any amount of literal '-'
            while !self.is_eof() && self.regex_bytes[self.pos] == b'-' {
                self.pos += 1;
            }
        }
        Ok(())
    }

    /// Parses an ASCII char class, e.g., `[:alnum:]`. If successful, advances the parser beyond the closing `]`.
    ///
    /// **Important.** The caller is responsible for rewinding the parser position if `Ok(false)` is returned.
    const fn try_parse_ascii_class(&mut self) -> bool {
        const CLASSES: &[&[u8]] = &[b"alnum", b"alpha", b"ascii", b"blank", b"cntrl", b"digit"];

        debug_assert!(self.regex_bytes[self.pos] == b'[');
        self.pos += 1;

        if self.is_eof() || self.regex_bytes[self.pos] != b':' {
            return false;
        }

        self.pos += 1;
        if self.is_eof() {
            return false;
        }
        if self.regex_bytes[self.pos] == b'^' {
            self.pos += 1;
            if self.is_eof() {
                return false;
            }
        }

        let is_known_class = self.gobble_any(CLASSES);
        // ^ Immediately rewind the parse position so we don't forget about it.
        if !is_known_class {
            return false;
        }

        !self.is_eof() && self.gobble(b":]")
    }

    const fn parse_set_class_range(&mut self) -> Result<(), Error> {
        let start_pos = self.pos;
        let start_item = const_try!(self.parse_set_class_item());
        if self.is_eof() {
            return Err(self.error(ErrorKind::UnfinishedSet, self.pos));
        }

        let ch = self.regex_bytes[self.pos];
        if ch != b'-' || self.matches_any(self.pos..self.pos + 2, &[b"-]", b"--"]) {
            // Not a range; we're done.
            return Ok(());
        }

        let PrimitiveKind::Literal(range_start) = start_item else {
            return Err(self.error(ErrorKind::InvalidRangeStart, start_pos));
        };

        debug_assert!(ch == b'-');
        self.pos += 1;
        const_try!(self.push_ast(self.pos - 1, Ast::SetRange));

        let end_start_pos = self.pos;
        let PrimitiveKind::Literal(range_end) = const_try!(self.parse_set_class_item()) else {
            return Err(self.error(ErrorKind::InvalidRangeEnd, end_start_pos));
        };

        if range_start > range_end {
            return Err(self.error(ErrorKind::InvalidRange, start_pos));
        }
        Ok(())
    }

    const fn parse_set_class_item(&mut self) -> Result<PrimitiveKind, Error> {
        let Some((ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
            return Err(self.error(ErrorKind::UnfinishedSet, self.pos));
        };
        if ch == '\\' {
            self.parse_escape()
        } else {
            self.pos = next_pos;
            Ok(PrimitiveKind::Literal(ch))
        }
    }

    const fn step(&mut self) -> Result<ops::ControlFlow<()>, Error> {
        let Some((current_ch, next_pos)) = split_first_char(self.regex_bytes, self.pos) else {
            if self.group_depth > 0 {
                return Err(self.error(ErrorKind::UnfinishedGroup, self.regex_bytes.len()));
            }
            return Ok(ops::ControlFlow::Break(()));
        };
        match current_ch {
            '(' => {
                const_try!(self.parse_group_start());
                self.is_empty_last_item = true;
            }
            ')' => {
                const_try!(self.end_group());
                self.is_empty_last_item = false;
            }
            '|' => {
                // Gobble the alteration.
                self.pos += 1;
                const_try!(self.push_ast(self.pos - 1, Ast::Alteration));
                self.is_empty_last_item = true;
            }
            '[' => {
                const_try!(self.parse_set_class());
                self.is_empty_last_item = false;
            }
            '?' | '*' | '+' => {
                const_try!(self.parse_uncounted_repetition());
                self.is_empty_last_item = false;
            }
            '{' => {
                const_try!(self.parse_counted_repetition());
                self.is_empty_last_item = false;
            }
            _ => {
                const_try!(self.parse_primitive(current_ch, next_pos));
                self.is_empty_last_item = false;
            }
        }
        Ok(ops::ControlFlow::Continue(()))
    }
}

/// Tries to validate the provided regular expression.
pub const fn try_validate(regex: &str) -> Result<(), Error> {
    let mut state = <ParseState>::new(regex);
    loop {
        match state.step() {
            Err(err) => return Err(err),
            Ok(ops::ControlFlow::Break(())) => break,
            Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
        }
    }

    Ok(())
}

#[track_caller]
pub const fn validate(regex: &str) {
    if let Err(err) = try_validate(regex) {
        err.compile_panic(regex);
    }
}

pub const fn try_parse<const CAP: usize>(regex: &str) -> Result<SyntaxSpans<CAP>, Error> {
    let mut state = ParseState::custom(regex, true);
    loop {
        match state.step() {
            Err(err) => return Err(err),
            Ok(ops::ControlFlow::Break(())) => {
                return match state.spans {
                    Some(spans) => Ok(spans),
                    None => panic!("no AST"),
                }
            }
            Ok(ops::ControlFlow::Continue(())) => { /* continue */ }
        }
    }
}

#[track_caller]
pub const fn parse<const CAP: usize>(regex: &str) -> SyntaxSpans<CAP> {
    match try_parse(regex) {
        Ok(spans) => spans,
        Err(err) => err.compile_panic(regex),
    }
}
