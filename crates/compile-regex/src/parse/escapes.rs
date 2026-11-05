//! Parsing escapes.

use super::{types::PrimitiveKind, ParseState};
use crate::{
    ast::Node,
    errors::{Error, ErrorKind},
    utils::{is_escapable_char, is_meta_char},
};

impl<const CAP: usize> ParseState<'_, CAP> {
    pub(super) const fn parse_escape(&mut self) -> Result<PrimitiveKind, Error> {
        let start_pos = self.pos;
        debug_assert!(self.regex_bytes[self.pos] == b'\\');
        self.pos += 1;

        let Some(current_char) = self.ascii_char() else {
            return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
        };
        // Gobble the escaped single ASCII char
        self.pos += 1;

        match current_char {
            b'0'..=b'9' => Err(self.error(start_pos, ErrorKind::UnsupportedBackref)),
            b'x' | b'u' | b'U' => {
                let ch = const_try!(self.parse_hex_escape(start_pos, current_char));
                const_try!(self.push_ast(start_pos, Node::HexEscape));
                Ok(PrimitiveKind::Literal(ch))
            }
            b'p' | b'P' => Err(self.error(start_pos, ErrorKind::UnicodeClassesNotSupported)),
            b'd' | b's' | b'w' | b'D' | b'S' | b'W' => {
                const_try!(self.push_ast(start_pos, Node::PerlClass));
                Ok(PrimitiveKind::PerlClass)
            }

            b'n' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\n'))
            }
            b't' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\t'))
            }
            b'r' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\r'))
            }
            b'a' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x07'))
            }
            b'f' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0C'))
            }
            b'v' => {
                const_try!(self.push_ast(start_pos, Node::EscapedLiteral));
                Ok(PrimitiveKind::Literal('\x0B'))
            }

            b'A' | b'z' | b'B' | b'<' | b'>' => {
                const_try!(self.push_ast(start_pos, Node::StdAssertion));
                Ok(PrimitiveKind::Other)
            }
            b'b' => {
                if !matches!(self.ascii_char(), Some(b'{'))
                    || !const_try!(self.try_parse_word_boundary(start_pos))
                {
                    const_try!(self.push_ast(start_pos, Node::StdAssertion));
                }
                Ok(PrimitiveKind::Other)
            }
            ch if is_meta_char(ch) => {
                const_try!(self.push_ast(start_pos, Node::EscapedChar { meta: true }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            ch if is_escapable_char(ch) => {
                const_try!(self.push_ast(start_pos, Node::EscapedChar { meta: false }));
                Ok(PrimitiveKind::Literal(ch as char))
            }
            _ => Err(self.error(start_pos, ErrorKind::UnsupportedEscape)),
        }
    }

    const fn try_parse_word_boundary(&mut self, escape_start: usize) -> Result<bool, Error> {
        const fn is_valid_char(ch: u8) -> bool {
            matches!(ch, b'A'..=b'Z' | b'a'..=b'z' | b'-')
        }

        const KNOWN_BOUNDARIES: &[&[u8]] = &[b"start", b"end", b"start-half", b"end-half"];

        let backup = self.backup();
        debug_assert!(self.regex_bytes[self.pos] == b'{');
        self.pos += 1;

        const_try!(self.gobble_whitespace_and_comments());
        let start_pos = self.pos;
        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedWordBoundary));
        }

        if !is_valid_char(self.regex_bytes[self.pos]) {
            self.restore(&backup);
            return Ok(false); // not a word boundary specifier
        }

        while !self.is_eof() && is_valid_char(self.regex_bytes[self.pos]) {
            self.pos += 1;
        }
        let end_pos = self.pos;
        const_try!(self.gobble_whitespace_and_comments());

        if self.ignore_whitespace {
            // `regex-syntax` allows whitespace / comments *inside* the specifier, which looks weird, so we don't allow it.
            if let Some(ch) = self.peek_whitespace(self.pos) {
                if ch.is_ascii() && is_valid_char(ch as u8) {
                    return Err(self.disallowed_error(end_pos));
                }
            }
        }

        if self.is_eof() || self.regex_bytes[self.pos] != b'}' {
            return Err(self.error(start_pos, ErrorKind::UnfinishedWordBoundary));
        }

        // Check whether the boundary specification is known.
        if !self.matches_any(start_pos..end_pos, KNOWN_BOUNDARIES) {
            return Err(ErrorKind::UnknownWordBoundary.with_position(start_pos..end_pos));
        }

        self.pos += 1; // gobble '}'
        const_try!(self.push_ast(escape_start, Node::StdAssertion));
        Ok(true)
    }

    /// Parses a hex-escaped char. The parser position is after the marker ('x', 'u' or 'U').
    ///
    /// Unlike `regex-syntax`, we don't allow any whitespace / comments *inside* the escape, so it's closer to Rust syntax,
    /// and doesn't lead to terribly looking regexes:
    ///
    /// ```text
    /// \u # can you guess
    ///   0 # this is
    /// 1 2 3 # a hex escape?
    /// ```
    const fn parse_hex_escape(&mut self, start_pos: usize, marker_ch: u8) -> Result<char, Error> {
        let Some(current_char) = self.ascii_char() else {
            return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
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
                _ if self.ignore_whitespace && digit.is_ascii_whitespace() => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedWhitespace));
                }
                b'#' if self.ignore_whitespace => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedComment));
                }
                _ => return Err(self.error(start_pos, ErrorKind::InvalidHex)),
            };
            if self.pos >= first_digit_pos + 8 {
                return Err(self.error(start_pos, ErrorKind::NonUnicodeHex));
            }
            // No overflow can happen due to the check above
            hex = hex * 16 + digit as u32;
        }

        if self.is_eof() {
            return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
        }

        // Gobble the terminating '}'
        debug_assert!(self.regex_bytes[self.pos] == b'}');
        self.pos += 1;

        if self.pos == first_digit_pos + 1 {
            Err(self.error(start_pos, ErrorKind::EmptyHex))
        } else {
            match char::from_u32(hex) {
                Some(ch) => Ok(ch),
                None => Err(self.error(start_pos, ErrorKind::NonUnicodeHex)),
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
                return Err(self.error(start_pos, ErrorKind::UnfinishedEscape));
            }
            let digit = self.regex_bytes[self.pos];
            self.pos += 1; // Advance immediately to get the correct error span

            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ if self.ignore_whitespace && digit.is_ascii_whitespace() => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedWhitespace));
                }
                b'#' if self.ignore_whitespace => {
                    // Return a more precise error
                    return Err(self.error(self.pos - 1, ErrorKind::DisallowedComment));
                }
                _ => return Err(self.error(start_pos, ErrorKind::InvalidHex)),
            };
            // No overflow can happen.
            hex = hex * 16 + digit as u32;
        }

        match char::from_u32(hex) {
            Some(ch) => Ok(ch),
            None => Err(self.error(start_pos, ErrorKind::NonUnicodeHex)),
        }
    }
}
